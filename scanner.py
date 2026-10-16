
import ipaddress
import json
import re
import socket
import time
import urllib.robotparser
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from datetime import datetime, timezone
from functools import partial
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import Timeout
from urllib3.util.connection import create_connection


SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce certain content injection risks.",
    "Strict-Transport-Security": "Encourages browsers to use HTTPS.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Can help protect against clickjacking.",
    "Referrer-Policy": "Controls referrer information.",
    "Permissions-Policy": "Restricts access to browser features.",
}

USER_AGENT = "SecureScan/2.0"
REQUEST_TIMEOUT = (5, 10)
MAX_REDIRECTS = 5
MAX_PAGE_BYTES = 256 * 1024
MAX_CRAWL_PAGES = 10
MAX_LINKS_PER_PAGE = 100
MAX_SITEMAPS = 2
MAX_SITEMAP_URLS = 100


class ScanCancelled(Exception):
    """Raised when the caller requests cancellation between requests."""


def _raise_if_cancelled(cancel_event):
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled("Scan cancelled by the user.")


def _resolve_public_addresses(hostname, port):
    """Resolve a hostname and reject the result if any IP is non-public."""
    try:
        answers = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise ValueError(
            "The hostname could not be resolved. Check the spelling "
            "or confirm that the domain exists and has DNS records."
        ) from error

    addresses = []

    for item in answers:
        try:
            address = ipaddress.ip_address(item[4][0])
        except (ValueError, IndexError) as error:
            raise ValueError(
                "The domain returned an invalid IP address."
            ) from error

        if not address.is_global:
            raise ValueError(
                "This domain resolves to a private or non-public IP address."
            )

        if str(address) not in addresses:
            addresses.append(str(address))

    if not addresses:
        raise ValueError("The hostname could not be resolved.")

    # Prefer IPv4 where available; some networks have broken IPv6 routes.
    addresses.sort(key=lambda value: ipaddress.ip_address(value).version)
    return addresses


class _PinnedHTTPConnection(HTTPConnection):
    """Connect directly to a validated IP without another DNS lookup."""

    def __init__(self, *args, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        try:
            return create_connection(
                (self.pinned_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.timeout as error:
            raise ConnectTimeoutError(
                self, f"Connection to {self.host} timed out."
            ) from error
        except OSError as error:
            raise NewConnectionError(
                self,
                f"Could not connect to validated address: {error}",
            ) from error


class _PinnedHTTPSConnection(HTTPSConnection):
    """Pin the TCP IP while retaining the original TLS hostname."""

    def __init__(self, *args, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        try:
            return create_connection(
                (self.pinned_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.timeout as error:
            raise ConnectTimeoutError(
                self, f"Connection to {self.host} timed out."
            ) from error
        except OSError as error:
            raise NewConnectionError(
                self,
                f"Could not connect to validated address: {error}",
            ) from error


class _SafeResponse:
    """Small response wrapper compatible with the scanner's needs."""

    def __init__(self, raw_response, pool, url, body=b"", connected_ip=None):
        self.raw = raw_response
        self._pool = pool
        self.status_code = raw_response.status
        self.headers = dict(raw_response.headers)
        get_all = getattr(raw_response.headers, "getlist", None)
        self.set_cookie_headers = (
            get_all("Set-Cookie") if callable(get_all) else []
        )
        self.url = url
        self.body = body
        self.connected_ip = connected_ip
        self._closed = False

    def close(self):
        if self._closed:
            return

        self._closed = True
        try:
            self.raw.close()
        finally:
            self._pool.close()


def _safe_get(url, auth_token=None, method="GET", extra_headers=None):
    """
    Make one request to a previously validated URL.

    The original hostname is retained for HTTP Host and TLS certificate
    verification. The TCP socket connects to an IP that was validated
    immediately before creating the connection.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Please enter a valid domain name.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        addresses = _resolve_public_addresses(hostname, port)
    else:
        if not literal_ip.is_global:
            raise ValueError(
                "Private or non-public IP addresses are blocked."
            )
        addresses = [str(literal_ip)]

    pinned_ip = addresses[0]
    timeout = Timeout(connect=REQUEST_TIMEOUT[0], read=REQUEST_TIMEOUT[1])

    if parsed.scheme == "https":
        pool = HTTPSConnectionPool(
            host=hostname,
            port=port,
            timeout=timeout,
            retries=False,
            cert_reqs="CERT_REQUIRED",
            ca_certs=requests.certs.where(),
            assert_hostname=hostname,
            server_hostname=hostname,
        )
        pool.ConnectionCls = partial(
            _PinnedHTTPSConnection,
            pinned_ip=pinned_ip,
        )
    elif parsed.scheme == "http":
        pool = HTTPConnectionPool(
            host=hostname,
            port=port,
            timeout=timeout,
            retries=False,
        )
        pool.ConnectionCls = partial(
            _PinnedHTTPConnection,
            pinned_ip=pinned_ip,
        )
    else:
        raise ValueError("Only HTTP and HTTPS websites are supported.")

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    try:
        request_headers = {"User-Agent": USER_AGENT, **(extra_headers or {})}
        if auth_token:
            if parsed.scheme != "https":
                raise ValueError("Authentication tokens are only sent over HTTPS.")
            request_headers["Authorization"] = "Bearer " + auth_token
        raw_response = pool.urlopen(
            method,
            path,
            headers=request_headers,
            redirect=False,
            retries=False,
            preload_content=False,
            timeout=timeout,
        )
        content_type = str(raw_response.headers.get("Content-Type", "")).lower()
        body = (
            raw_response.read(MAX_PAGE_BYTES + 1, decode_content=True)
            if ("html" in content_type or "json" in content_type or "xml" in content_type
                    or path.lower().endswith(("/robots.txt", "/sitemap.xml"))) else b""
        )
        return _SafeResponse(raw_response, pool, url, body[:MAX_PAGE_BYTES], pinned_ip)
    except Exception:
        pool.close()
        raise


def normalize_url(website):
    """Validate and normalize a domain or HTTP(S) URL."""

    if not isinstance(website, str) or not website.strip():
        raise ValueError("Please enter a website URL.")

    website = website.strip()

    if any(char.isspace() for char in website):
        raise ValueError("The URL contains unescaped spaces.")

    if "://" not in website:
        website = "https://" + website

    try:
        parsed = urlparse(website)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("The website address or port is invalid.") from error

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS websites are supported.")

    if not hostname:
        raise ValueError("Please enter a valid domain name.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "Website addresses containing credentials are blocked."
        )

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("The website port is invalid.")

    is_ipv6 = ":" in hostname

    try:
        hostname = (
            hostname.rstrip(".").encode("idna").decode("ascii").lower()
        )
    except UnicodeError as error:
        raise ValueError("The domain name format is invalid.") from error

    if not hostname or len(hostname) > 253:
        raise ValueError("The domain name length is invalid.")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost targets are blocked.")

    if hostname.endswith((".local", ".internal", ".test", ".invalid")):
        raise ValueError("Local or reserved hostnames are blocked.")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not literal_ip.is_global:
            raise ValueError(
                "Private or non-public IP addresses are blocked."
            )
    else:
        labels = hostname.split(".")
        label_pattern = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
        )

        if len(labels) < 2:
            raise ValueError(
                "Please enter a complete domain, such as example.com."
            )

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not label_pattern.fullmatch(label)
            ):
                raise ValueError("The domain name format is invalid.")

        selected_port = port or (443 if scheme == "https" else 80)
        _resolve_public_addresses(hostname, selected_port)

    netloc = f"[{hostname}]" if is_ipv6 else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunparse((
        scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        "",
    ))


def validate_url(website):
    """Backward-compatible URL validation."""
    return normalize_url(website)


def _header_quality_issue(header, value, headers):
    """Return a finding for clearly weak values of supported headers."""
    value = str(value or "").strip()
    lower = value.lower()
    if header == "Content-Security-Policy":
        if not value:
            return ("Empty Content-Security-Policy", "The enforcing CSP header is present but empty.", "Medium")
        if ("default-src *" in lower or "script-src *" in lower
                or "'unsafe-eval'" in lower or "'unsafe-inline'" in lower
                or not re.search(r"(?:^|;)\s*(?:default-src|script-src)\b", lower)):
            return ("Weak Content-Security-Policy", f"Observed policy: {value}", "Medium")
    elif header == "Strict-Transport-Security":
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", lower)
        if not match or int(match.group(1)) < 15552000:
            return ("Weak Strict-Transport-Security policy", f"Observed policy: {value}. A max-age of at least 180 days is generally recommended.", "Low")
    elif header == "X-Content-Type-Options" and lower != "nosniff":
        return ("Misconfigured X-Content-Type-Options", f"Observed value: {value}", "Low")
    elif header == "X-Frame-Options" and lower not in {"deny", "sameorigin"}:
        if "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            return ("Weak X-Frame-Options policy", f"Observed value: {value}", "Low")
    elif header == "Referrer-Policy" and lower in {"unsafe-url", "no-referrer-when-downgrade"}:
        return ("Weak Referrer-Policy", f"Observed value: {value}", "Low")
    elif header == "Permissions-Policy" and (not value or "=*" in lower):
        return ("Broad Permissions-Policy", f"Observed value: {value or '(empty)'}", "Low")
    return None


def _inspect_cookie_headers(response, https, add_finding):
    """Check cookie attributes without retaining cookie values."""
    cookie_headers = getattr(response, "set_cookie_headers", None)
    if cookie_headers is None:
        cookie_headers = []
    if not cookie_headers:
        value = response.headers.get("Set-Cookie")
        if isinstance(value, (list, tuple)):
            cookie_headers = list(value)
        elif value:
            cookie_headers = [value]

    results = []
    for header in cookie_headers:
        parts = [part.strip() for part in str(header).split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {}
        for part in parts[1:]:
            key, _, val = part.partition("=")
            attrs[key.strip().lower()] = val.strip().lower() if val else True
        check = {
            "name": name[:100],
            "secure": "secure" in attrs,
            "http_only": "httponly" in attrs,
            "same_site": attrs.get("samesite"),
        }
        results.append(check)
        if not check["secure"]:
            transport = "over HTTPS" if https else "on an HTTP response"
            add_finding("Medium", f"Cookie missing Secure attribute: {name[:60]}", f"Set-Cookie was observed without the Secure attribute {transport}.")
        if not check["http_only"]:
            add_finding("Low", f"Cookie missing HttpOnly attribute: {name[:60]}", "Set-Cookie was observed without HttpOnly, so browser scripts may be able to read it.")
        if not check["same_site"]:
            add_finding("Low", f"Cookie missing SameSite attribute: {name[:60]}", "Set-Cookie was observed without an explicit SameSite policy.")
        elif check["same_site"] == "none" and not check["secure"]:
            add_finding("Medium", f"Cookie SameSite=None without Secure: {name[:60]}", "SameSite=None cookies require Secure in modern browsers.")
    return results


class _PageSecurityParser(HTMLParser):
    """Collect a small, passive summary of forms and executable resources."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.password_forms = []
        self.forms = []
        self.mixed_content = []
        self.links = []
        self.resources = []
        self.api_spec_hints = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._form = {
                "method": (values.get("method") or "get").strip().lower(),
                "action": values.get("action", "").strip(),
                "has_password": False,
                "input_fields": [],
            }
        elif tag.lower() == "input" and self._form:
            input_type = values.get("type", "text").strip().lower()
            self._form["input_fields"].append({
                "name": values.get("name", "")[:100],
                "type": input_type[:30],
            })
            if input_type == "password":
                self._form["has_password"] = True
        elif tag.lower() in {"script", "iframe", "object"}:
            resource = values.get("src") or values.get("data")
            if resource and len(self.resources) < MAX_LINKS_PER_PAGE:
                self.resources.append({"element": tag.lower(), "url": resource[:300]})
            if resource and resource.lower().startswith("http://"):
                self.mixed_content.append({"element": tag.lower(), "url": resource[:300]})
        elif tag.lower() == "a" and values.get("href") and len(self.links) < MAX_LINKS_PER_PAGE:
            href = values["href"].strip()
            self.links.append(href)
            lowered = href.lower()
            if any(marker in lowered for marker in ("openapi", "swagger", "api-docs")):
                self.api_spec_hints.append(href[:300])

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._form:
            self.forms.append({
                "method": self._form["method"],
                "action": self._form["action"],
                "contains_password": self._form["has_password"],
                "input_fields": self._form["input_fields"],
            })
            if self._form["has_password"]:
                self.password_forms.append(self._form)
            self._form = None


def _inspect_page_security(response, add_finding):
    """Passively inspect returned HTML; never submit forms or follow links."""
    headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
    content_type = headers.get("content-type", "").lower()
    body = getattr(response, "body", b"")
    if "json" in content_type and body:
        try:
            document = json.loads(body.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            document = None
        if isinstance(document, dict) and isinstance(document.get("paths"), dict) and (document.get("openapi") or document.get("swagger")):
            paths = []
            for path, operations in document["paths"].items():
                if not isinstance(operations, dict):
                    continue
                methods = [str(method).upper() for method in operations if str(method).lower() in {"get", "post", "put", "patch", "delete", "options", "head"}]
                paths.append({"path": str(path)[:300], "methods": methods})
                if len(paths) >= 100:
                    break
            info = document.get("info")
            api_title = info.get("title") if isinstance(info, dict) else None
            return {
                "html_inspected": False, "password_forms": 0, "mixed_content": 0,
                "links": [], "forms": [], "resources": [], "api_spec_hints": [],
                "api_spec": {
                    "title": str(api_title or "OpenAPI document")[:200],
                    "version": str(document.get("openapi") or document.get("swagger")),
                    "endpoint_count": len(document["paths"]),
                    "paths": paths,
                },
            }
    if "html" not in content_type or not body:
        return {"html_inspected": False, "password_forms": 0, "mixed_content": 0,
                "links": [], "forms": [], "resources": [], "api_spec_hints": [], "api_spec": None}

    parser = _PageSecurityParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:
        return {"html_inspected": False, "password_forms": 0, "mixed_content": 0,
                "links": [], "forms": [], "resources": [], "api_spec_hints": [], "api_spec": None}

    page_scheme = urlparse(response.url).scheme.lower()
    for form in parser.password_forms:
        action = urljoin(response.url, form["action"] or response.url)
        action_scheme = urlparse(action).scheme.lower()
        if form["method"] == "get":
            add_finding(
                "High", "Password form uses GET",
                f"A password field was found in a GET form posting to {action}. GET parameters can appear in URLs, browser history, and server logs.",
            )
        elif page_scheme == "https" and action_scheme == "http":
            add_finding(
                "High", "Password form submits over HTTP",
                f"A password field was found in a form posting to {action} over unencrypted HTTP.",
            )

    if page_scheme == "https" and parser.mixed_content:
        urls = ", ".join(item["url"] for item in parser.mixed_content[:5])
        add_finding(
            "Medium", "Active mixed content detected",
            f"HTTPS HTML references executable resources over HTTP: {urls}",
        )

    return {
        "html_inspected": True,
        "password_forms": len(parser.password_forms),
        "mixed_content": len(parser.mixed_content),
        "page_size_capped": len(body) >= MAX_PAGE_BYTES,
        "links": parser.links,
        "forms": parser.forms,
        "resources": parser.resources,
        "api_spec_hints": parser.api_spec_hints,
        "api_spec": None,
    }


def _origin(url):
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _crawl_same_origin(root_url, root_links, auth_token, add_finding,
                       progress_callback=None, max_pages=MAX_CRAWL_PAGES,
                       cancel_event=None):
    """GET a bounded set of same-origin links while honoring robots.txt."""
    pages = [{"url": root_url, "status_code": None, "state": "checked"}]
    skipped = []
    robots_url = urljoin(root_url, "/robots.txt")
    robots_response = None
    robots = urllib.robotparser.RobotFileParser()
    sitemap_urls = []
    robots.set_url(robots_url)
    try:
        _raise_if_cancelled(cancel_event)
        robots_response = _safe_get(robots_url, auth_token=auth_token)
        if 200 <= robots_response.status_code < 300:
            robots_lines = robots_response.body.decode("utf-8", errors="replace").splitlines()
            robots.parse(robots_lines)
            sitemap_urls = [
                line.split(":", 1)[1].strip()
                for line in robots_lines
                if line.lower().startswith("sitemap:") and ":" in line
            ][:MAX_SITEMAPS]
        elif robots_response.status_code == 404:
            robots.parse([])
        else:
            robots.parse(["User-agent: *", "Disallow: /"])
            skipped.append({"url": robots_url, "reason": "robots.txt could not be read; crawl stopped"})
    except ScanCancelled:
        raise
    except Exception as error:
        robots.parse(["User-agent: *", "Disallow: /"])
        skipped.append({"url": robots_url, "reason": f"robots.txt lookup failed: {type(error).__name__}"})
    finally:
        if robots_response is not None:
            robots_response.close()

    if skipped:
        return pages, skipped

    queue = [urljoin(root_url, link) for link in root_links]
    for sitemap_url in sitemap_urls:
        sitemap_response = None
        try:
            _raise_if_cancelled(cancel_event)
            sitemap_url = urljoin(root_url, sitemap_url)
            if _origin(sitemap_url) != _origin(root_url):
                skipped.append({"url": sitemap_url[:300], "reason": "external sitemap is outside the scanned origin"})
                continue
            sitemap_path = urlparse(sitemap_url).path or "/"
            if not robots.can_fetch(USER_AGENT, sitemap_path):
                skipped.append({"url": sitemap_url[:300], "reason": "sitemap disallowed by robots.txt"})
                continue
            sitemap_response = _safe_get(sitemap_url, auth_token=auth_token)
            if not 200 <= sitemap_response.status_code < 300:
                skipped.append({"url": sitemap_url[:300], "reason": f"sitemap returned HTTP {sitemap_response.status_code}"})
                continue
            root = ET.fromstring(sitemap_response.body)
            for element in root.iter():
                if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text:
                    queue.append(element.text.strip())
                    if len(queue) >= MAX_SITEMAP_URLS:
                        break
        except ScanCancelled:
            raise
        except Exception as error:
            skipped.append({"url": str(sitemap_url)[:300], "reason": f"sitemap could not be parsed: {type(error).__name__}"})
        finally:
            if sitemap_response is not None:
                sitemap_response.close()
    visited = {root_url}
    while queue and len(pages) < max_pages:
        _raise_if_cancelled(cancel_event)
        candidate = queue.pop(0)
        try:
            candidate = urljoin(root_url, candidate)
            candidate_parsed = urlparse(candidate)
            if (
                candidate_parsed.scheme.lower() not in {"http", "https"}
                or (candidate_parsed.hostname or "").lower() != (urlparse(root_url).hostname or "").lower()
            ):
                skipped.append({"url": candidate[:300], "reason": "outside the scanned hostname"})
                continue
            candidate = normalize_url(candidate)
            if _origin(candidate) != _origin(root_url):
                skipped.append({"url": candidate, "reason": "outside the scanned origin"})
                continue
            parsed = urlparse(candidate)
            if not robots.can_fetch(USER_AGENT, parsed.path or "/"):
                skipped.append({"url": candidate, "reason": "disallowed by robots.txt"})
                continue
        except ValueError as error:
            skipped.append({"url": str(candidate)[:300], "reason": str(error)})
            continue
        if candidate in visited:
            continue
        visited.add(candidate)
        if progress_callback:
            progress_callback("crawl", f"Checking page {len(pages) + 1} of {max_pages}", len(pages), max_pages)
        response = None
        try:
            response = _safe_get(candidate, auth_token=auth_token)
            page_findings = []

            def record_page_finding(severity, title, details):
                page_findings.append((severity, title, f"{details} Page: {candidate}"))

            response_headers = {
                str(name).lower(): str(value)
                for name, value in response.headers.items()
            }
            is_https = urlparse(candidate).scheme.lower() == "https"
            headers_checked = 0
            for header, explanation in SECURITY_HEADERS.items():
                if header == "Strict-Transport-Security" and not is_https:
                    continue
                headers_checked += 1
                value = response_headers.get(header.lower())
                if value is None:
                    record_page_finding("Low", f"Missing {header}", explanation)
                else:
                    issue = _header_quality_issue(header, value, response_headers)
                    if issue:
                        severity, title, details = issue
                        record_page_finding(severity, title, details)

            cookie_checks = _inspect_cookie_headers(
                response, is_https, record_page_finding
            )
            page_checks = _inspect_page_security(
                response,
                record_page_finding,
            )
            for severity, title, details in page_findings:
                add_finding(severity, title, details)
            pages.append({
                "url": candidate,
                "status_code": response.status_code,
                "state": "checked",
                "html_inspected": page_checks["html_inspected"],
                "headers_checked": headers_checked,
                "cookies_checked": len(cookie_checks),
                "forms_found": page_checks.get("forms", []),
                "resource_count": len(page_checks.get("resources", [])),
                "api_spec_hints": page_checks.get("api_spec_hints", []),
                "api_spec": page_checks.get("api_spec"),
                "finding_count": len(page_findings),
            })
            queue.extend(urljoin(candidate, link) for link in page_checks.get("links", []))
        except Exception as error:
            pages.append({"url": candidate, "status_code": None, "state": "unavailable", "error": type(error).__name__})
        finally:
            if response is not None:
                response.close()

    if queue:
        skipped.extend({"url": str(url)[:300], "reason": "page limit reached"} for url in queue[:20])
    return pages, skipped


def scan_website(website, profile="quick", auth_token=None, progress_callback=None,
                 cancel_event=None):
    """Run bounded passive checks, optionally crawling same-origin pages."""

    website = validate_url(website)
    if profile not in {"quick", "thorough", "active"}:
        raise ValueError("Scan profile must be quick, thorough, or active.")
    if auth_token and urlparse(website).scheme.lower() != "https":
        raise ValueError("Authentication tokens are only supported for HTTPS targets.")

    report = {
        "scanner": "SecureScan",
        "scan_profile": profile,
        "scope": (
            "One page; passive headers, HTML, cookies, TLS and domain metadata."
            if profile == "quick" else
            f"Up to {MAX_CRAWL_PAGES} same-origin pages, honoring robots.txt; GET only. Forms are never submitted."
            if profile == "thorough" else
            "Passive checks plus one non-destructive CORS preflight OPTIONS request. No form submissions or exploit payloads."
        ),
        "target": website,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "http_status": None,
        "status_code": None,
        "final_url": None,
        "https": None,
        "redirects": [],
        "findings": [],
        "summary": {},
    }

    def add_finding(severity, title, details):
        report["findings"].append({
            "severity": severity,
            "title": title,
            "details": details,
            "evidence": details,
            "confidence": "High",
        })

    print("\nConnecting to website...")
    print("Normalized URL:", website)

    current_url = website
    visited_urls = set()
    response = None

    try:
        if progress_callback:
            progress_callback("http", "Fetching the starting page", 0, 1)
        for redirect_number in range(MAX_REDIRECTS + 1):
            _raise_if_cancelled(cancel_event)
            current_url = validate_url(current_url)

            if current_url in visited_urls:
                add_finding(
                    "INFO",
                    "Redirect loop detected",
                    "A previously visited URL was reached again. "
                    "The scanner stopped following redirects.",
                )
                break

            visited_urls.add(current_url)
            response = _safe_get(current_url, auth_token=auth_token) if auth_token else _safe_get(current_url)

            location = response.headers.get("Location")
            status_code = response.status_code

            if not (300 <= status_code < 400) or not location:
                break

            destination = urljoin(current_url, location)

            add_finding(
                "INFO",
                "Redirect detected",
                f"HTTP {status_code}: {current_url} redirects to "
                f"{destination}. The destination is validated before "
                "the next connection.",
            )

            report["redirects"].append({
                "status_code": status_code,
                "from": current_url,
                "to": destination,
            })

            # Validate the destination before closing the current response.
            destination = validate_url(destination)

            source_host = urlparse(current_url).hostname
            destination_host = urlparse(destination).hostname
            if source_host != destination_host or (
                auth_token and _origin(current_url) != _origin(destination)
            ):
                add_finding(
                    "INFO",
                    "Credential redirect not followed" if auth_token else "Cross-domain redirect not followed",
                    f"The site redirects to {destination}. SecureScan stopped at the redirect so credentials are not sent to another origin and a separate domain is not scanned without a separate authorization confirmation.",
                )
                break

            # If it loops back, retain the current response for the report.
            if destination in visited_urls:
                add_finding(
                    "INFO",
                    "Redirect loop detected",
                    "A previously visited URL was reached again. "
                    "The scanner stopped following redirects.",
                )
                break

            # Keep the last response when the redirect limit is reached.
            if redirect_number >= MAX_REDIRECTS:
                add_finding(
                    "INFO",
                    "Redirect limit reached",
                    f"The scanner stopped after {MAX_REDIRECTS} redirects.",
                )
                break

            response.close()
            response = None
            current_url = destination

        if response is None:
            raise requests.exceptions.ConnectionError(
                "No final HTTP response was received."
            )

        report["http_status"] = response.status_code
        report["status_code"] = response.status_code
        report["final_url"] = response.url
        report["server_ip"] = getattr(response, "connected_ip", None)
        report["https"] = (
            urlparse(report["final_url"]).scheme.lower() == "https"
        )
        report["status"] = "completed"

        print("Final URL:", report["final_url"])
        print("HTTP status:", response.status_code)
        print("HTTPS:", "Yes" if report["https"] else "No")
        print("\nChecking security headers...")

        if response.status_code >= 400:
            add_finding(
                "INFO",
                "HTTP error response",
                f"The server returned status {response.status_code}.",
            )

        if not report["https"]:
            add_finding(
                "REVIEW",
                "HTTP connection",
                "The final response uses HTTP rather than HTTPS.",
            )

        found = 0
        missing = 0
        skipped = 0
        response_headers = {
            name.lower(): str(value)
            for name, value in response.headers.items()
        }

        for header, explanation in SECURITY_HEADERS.items():
            if (
                header == "Strict-Transport-Security"
                and not report["https"]
            ):
                print("[SKIPPED]", header)
                skipped += 1
                continue

            value = response_headers.get(header.lower())
            if value is not None:
                print("[FOUND]", header)
                found += 1
                issue = _header_quality_issue(header, value, response_headers)
                if issue:
                    title, details, severity = issue
                    add_finding(severity, title, details)
            else:
                print("[INFO] Missing", header)
                add_finding("INFO", f"Missing {header}", explanation)
                missing += 1

        report["cookie_checks"] = _inspect_cookie_headers(
            response, report["https"], add_finding
        )
        report["page_checks"] = _inspect_page_security(response, add_finding)

        report["active_checks"] = []
        if profile == "active":
            if not report["https"]:
                report["active_checks"].append({
                    "check": "CORS preflight", "status": "skipped",
                    "reason": "The CORS probe is only sent over HTTPS.",
                })
            else:
                probe_origin = "https://securescan.invalid"
                probe = None
                try:
                    _raise_if_cancelled(cancel_event)
                    if progress_callback:
                        progress_callback("active", "Checking CORS preflight behavior", 0, 1)
                    probe = _safe_get(
                        report["final_url"], auth_token=auth_token, method="OPTIONS",
                        extra_headers={
                            "Origin": probe_origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "authorization",
                        },
                    )
                    probe_headers = {str(k).lower(): str(v).strip() for k, v in probe.headers.items()}
                    allowed_origin = probe_headers.get("access-control-allow-origin", "")
                    allow_credentials = probe_headers.get("access-control-allow-credentials", "").lower() == "true"
                    allowed_methods = {
                        value.strip().upper()
                        for value in probe_headers.get("access-control-allow-methods", "").split(",")
                        if value.strip()
                    }
                    allowed_headers = {
                        value.strip().lower()
                        for value in probe_headers.get("access-control-allow-headers", "").split(",")
                        if value.strip()
                    }
                    credentials_preflight_allowed = (
                        "GET" in allowed_methods
                        and "authorization" in allowed_headers
                    )
                    if allowed_origin == probe_origin and allow_credentials and credentials_preflight_allowed:
                        add_finding(
                            "High", "CORS preflight accepts an untrusted origin with credentials",
                            "An OPTIONS preflight response accepted the SecureScan test origin, GET, and the Authorization header while allowing credentials. Review the CORS allowlist and credential policy.",
                        )
                        status = "risk"
                    elif allowed_origin == "*" and allow_credentials:
                        add_finding(
                            "Info", "CORS wildcard and credentials headers observed",
                            "The response combined Access-Control-Allow-Origin: * with credentials. Browsers reject this combination for credentialed reads, so verify actual policy behavior.",
                        )
                        status = "review"
                    else:
                        status = "checked"
                    report["active_checks"].append({
                        "check": "CORS preflight", "status": status,
                        "http_status": probe.status_code,
                        "allow_origin": allowed_origin or None,
                        "allow_credentials": allow_credentials,
                        "allow_methods": sorted(allowed_methods),
                        "allow_headers": sorted(allowed_headers),
                        "test_origin": probe_origin,
                    })
                except ScanCancelled:
                    raise
                except Exception as error:
                    report["active_checks"].append({
                        "check": "CORS preflight", "status": "unavailable",
                        "reason": type(error).__name__,
                    })
                finally:
                    if probe is not None:
                        probe.close()

        for header_name, label in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
            value = response_headers.get(header_name)
            if value:
                add_finding(
                    "INFO", f"Technology banner disclosed: {label}",
                    f"The response exposes {label}: {value[:200]}. Consider removing unnecessary version details.",
                )

        report["pages"] = [{
            "url": report["final_url"],
            "status_code": response.status_code,
            "state": "checked",
            "html_inspected": report["page_checks"]["html_inspected"],
            "headers_checked": found + missing,
            "cookies_checked": len(report["cookie_checks"]),
            "forms_found": report["page_checks"].get("forms", []),
            "resource_count": len(report["page_checks"].get("resources", [])),
            "api_spec_hints": report["page_checks"].get("api_spec_hints", []),
            "api_spec": report["page_checks"].get("api_spec"),
        }]
        report["pages_skipped"] = []
        if profile == "thorough":
            if progress_callback:
                progress_callback("crawl", "Reading robots.txt and selecting same-origin pages", 1, MAX_CRAWL_PAGES)
            report["pages"], report["pages_skipped"] = _crawl_same_origin(
                report["final_url"],
                report["page_checks"]["links"],
                auth_token,
                add_finding,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )
            if report["pages"]:
                report["pages"][0].update({
                    "status_code": response.status_code,
                    "html_inspected": report["page_checks"]["html_inspected"],
                    "headers_checked": found + missing,
                    "cookies_checked": len(report["cookie_checks"]),
                    "forms_found": report["page_checks"].get("forms", []),
                    "resource_count": len(report["page_checks"].get("resources", [])),
                    "api_spec_hints": report["page_checks"].get("api_spec_hints", []),
                    "api_spec": report["page_checks"].get("api_spec"),
                })

        report["summary"] = {
            "headers_found": found,
            "headers_missing": missing,
            "headers_skipped": skipped,
            "cookies_checked": len(report["cookie_checks"]),
            "html_inspected": report["page_checks"]["html_inspected"],
            "html_password_forms": report["page_checks"]["password_forms"],
            "active_mixed_content": report["page_checks"]["mixed_content"],
            "forms_found": len(report["page_checks"].get("forms", [])),
            "resources_found": len(report["page_checks"].get("resources", [])),
            "api_spec_hints": report["page_checks"].get("api_spec_hints", []),
            "pages_checked": len(report["pages"]),
            "pages_skipped": len(report["pages_skipped"]),
            "total_findings": len(report["findings"]),
        }

    except ScanCancelled:
        report["status"] = "cancelled"
        raise
    except (requests.exceptions.RequestException, ValueError):
        report["status"] = "failed"
        raise
    finally:
        if response is not None:
            response.close()

    lines = [
        "SIMPLE WEB VULNERABILITY SCANNER",
        "=" * 45,
        f"Target: {website}",
        f"Final URL: {report['final_url']}",
        f"HTTP status: {report['http_status']}",
        f"HTTPS: {'YES' if report['https'] else 'NO / UNAVAILABLE'}",
        f"Redirects: {len(report['redirects'])}",
        f"Scan time: {report['scan_time']}",
        "",
        "FINDINGS",
        "-" * 45,
    ]

    for finding in report["findings"]:
        lines.append(f"[{finding['severity']}] {finding['title']}")
        lines.append(f"  {finding['details']}")

    if not report["findings"]:
        lines.append("No findings from these basic checks.")

    lines.extend([
        "",
        "SUMMARY",
        "-" * 45,
        f"Headers found: {report['summary']['headers_found']}",
        f"Headers missing: {report['summary']['headers_missing']}",
        f"Headers skipped: {report['summary']['headers_skipped']}",
        f"Total findings: {len(report['findings'])}",
        "",
        "These checks do not prove whether a website is secure.",
        "Only scan websites you own or have permission to assess.",
    ])

    text_report = "\n".join(lines)
    print("\n" + text_report)

    with open("scan_report.txt", "w", encoding="utf-8") as file:
        file.write(text_report)

    with open("scan_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReports saved:")
    print("- scan_report.txt")
    print("- scan_report.json")

    return report


def main():
    print("=" * 45)
    print("SECURESCAN - WEBSITE SECURITY SCANNER")
    print("=" * 45)

    try:
        website = input(
            "Enter a domain or website URL "
            "(for example, google.com): "
        )
        authorization = input(
            "Confirm that you own this site or have permission to assess it (yes/no): "
        )
        if authorization.strip().lower() not in {"y", "yes"}:
            print("Scan cancelled. Only assess websites with permission.")
            return
        scan_website(website)

    except ValueError as error:
        print("Invalid website:", error)

    except requests.exceptions.Timeout:
        print("Error: The website took too long to respond.")

    except requests.exceptions.SSLError:
        print("Error: HTTPS certificate verification failed.")

    except requests.exceptions.RequestException as error:
        print("Connection error:", error)

    except OSError as error:
        print("System or file error:", error)


if __name__ == "__main__":
    main()
