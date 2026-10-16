import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests


USER_AGENT = "SecureScan-DomainIntelligence/1.0"

DNS_RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "CAA"]

LK_REGISTRY_LOOKUP_URL = "https://rs.domains.lk/domainsearch"
WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"


def get_domain_suffix_info(domain):
    """Return the TLD and, for country-code TLDs, its country code.

    This identifies the domain's suffix only; it does not imply the owner,
    registrar, website operator, or server is located in that country.
    """
    suffix = domain.rsplit(".", 1)[-1].lower()
    return {
        "top_level_domain": "." + suffix,
        "country_code_domain": suffix.upper() if len(suffix) == 2 and suffix.isalpha() else None,
    }


def query_first_archived_date(domain):
    """Find the earliest known successful HTML capture in the Wayback Machine.

    This is an estimate of when the site was first archived, not its creation
    or launch date. The external lookup is best-effort and has a short timeout.
    """
    try:
        response = requests.get(
            WAYBACK_CDX_URL,
            params={
                "url": domain,
                "output": "json",
                "fl": "timestamp,statuscode,mimetype",
                "filter": ["statuscode:200", "mimetype:text/html"],
                "collapse": "timestamp:4",
                "limit": "1",
            },
            headers={"User-Agent": USER_AGENT},
            timeout=(3, 5),
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list) or len(data) < 2:
            return None
        timestamp = data[1][0]
        if not isinstance(timestamp, str) or len(timestamp) < 8 or not timestamp[:8].isdigit():
            return None
        return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
    except (requests.RequestException, ValueError, TypeError, IndexError):
        return None


def normalize_domain(target):
    """Extract and validate a hostname from a URL or domain."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Please provide a domain name or URL.")

    target = target.strip()

    if "://" not in target:
        target = "https://" + target

    try:
        parsed = urlparse(target)
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError("The URL format is invalid.") from exc

    if not hostname:
        raise ValueError("The URL does not contain a valid hostname.")

    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The domain name format is invalid.") from exc

    if len(hostname) > 253:
        raise ValueError("The hostname is too long.")

    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal", ".test", ".invalid")
    ):
        raise ValueError("Local or reserved hostnames are not supported.")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if not ip.is_global:
            raise ValueError("Private or non-public IP addresses are not supported.")
        raise ValueError("Please provide a domain name rather than a direct IP.")

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    labels = hostname.split(".")

    if len(labels) < 2:
        raise ValueError("Please provide a complete domain name.")

    for label in labels:
        if not label or len(label) > 63 or not label_pattern.fullmatch(label):
            raise ValueError("The hostname format is invalid.")

    return hostname


def query_dns(domain):
    """Collect common DNS records for a domain."""

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    results = {}
    notes = []

    for record_type in DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(
                domain,
                record_type,
                raise_on_no_answer=False,
            )

            if answer.rrset is None:
                results[record_type] = []
                continue

            records = []

            for record in answer:
                if record_type == "MX":
                    records.append({
                        "priority": record.preference,
                        "mail_server": str(record.exchange).rstrip("."),
                    })
                elif record_type == "TXT":
                    records.append(
                        b"".join(record.strings).decode("utf-8", errors="replace")
                    )
                elif record_type == "NS":
                    records.append(str(record.target).rstrip("."))
                else:
                    records.append(record.to_text())

            results[record_type] = records

        except dns.resolver.NXDOMAIN:
            results[record_type] = []
            notes.append("The domain does not exist in DNS.")
            break
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NoNameservers:
            results[record_type] = []
            notes.append(f"No responding nameservers for {record_type}.")
        except dns.exception.Timeout:
            results[record_type] = []
            notes.append(f"The {record_type} lookup timed out.")
        except Exception as exc:
            results[record_type] = []
            notes.append(f"{record_type} lookup failed: {type(exc).__name__}.")

    results["_notes"] = notes
    return results


def query_email_security(domain):
    """Best-effort SPF, DMARC, and common-selector DKIM DNS checks.

    DKIM selectors are not published in a universal index, so the result is
    explicitly limited to the common selectors queried here.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1.5

    def txt_records(name):
        try:
            answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
            if answer.rrset is None:
                return [], "available"
            return ([b"".join(record.strings).decode("utf-8", errors="replace") for record in answer], "available")
        except dns.resolver.NXDOMAIN:
            return [], "available"
        except dns.resolver.NoAnswer:
            return [], "available"
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return [], "unavailable"
        except Exception:
            return [], "unavailable"

    root_txt, root_status = txt_records(domain)
    spf = [record for record in root_txt if record.lower().startswith("v=spf1")]
    dmarc_txt, dmarc_status = txt_records("_dmarc." + domain)
    dmarc = [record for record in dmarc_txt
             if record.lower().startswith("v=dmarc1")]
    selectors = ("google", "selector1", "selector2", "default", "s1")
    dkim = []
    for selector in selectors:
        selector_txt, _ = txt_records(f"{selector}._domainkey.{domain}")
        records = [record for record in selector_txt
                   if "v=dkim1" in record.lower() or "p=" in record.lower()]
        if records:
            dkim.append({"selector": selector, "records": records})
    return {
        "spf_records": spf,
        "spf_status": "found" if spf else ("not_found" if root_status == "available" else "unavailable"),
        "dmarc_records": dmarc,
        "dmarc_status": "found" if dmarc else ("not_found" if dmarc_status == "available" else "unavailable"),
        "dkim_records": dkim,
        "dkim_selectors_checked": list(selectors),
        "dkim_scope_note": "DKIM selectors are not centrally discoverable; only common selectors were checked.",
    }


def query_registration(domain):
    """Retrieve RDAP registration data when available.

    For .lk domains, include the official registry search URL.
    Registration details are not fabricated when RDAP cannot provide them.
    """

    domain = domain.lower().rstrip(".")
    rdap_domain = domain[4:] if domain.startswith("www.") else domain

    is_lk_domain = rdap_domain.endswith(".lk")

    result = {
        "available": False,
        "source": "LK Domain Registry" if is_lk_domain else "RDAP",
        "lookup_url": LK_REGISTRY_LOOKUP_URL if is_lk_domain else None,
        "registrant": None,
        "registrant_country": None,
        "category": None,
        "registry_status": None,
        "registrar": None,
        "registrar_country": None,
        "registration_date": None,
        "expiration_date": None,
        "last_updated": None,
        "status": [],
        "nameservers": [],
        "error": None,
    }

    url = f"https://rdap.org/domain/{rdap_domain}"

    try:
        response = requests.get(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/rdap+json, application/json",
            },
            timeout=(5, 10),
        )

        if response.status_code == 404:
            if is_lk_domain:
                result["error"] = (
                    "RDAP registration data is unavailable for this .lk domain. "
                    "Check the official LK Domain Registry website for registration "
                    "status, registrant, category, and expiry date. These details "
                    "have not been retrieved automatically."
                )
            else:
                result["error"] = (
                    "Registration data was not found. The hostname may be a "
                    "subdomain or the RDAP service may not support this domain."
                )
            return result

        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict):
            result["error"] = "The registration service returned invalid data."
            return result

        result["available"] = True
        result["source"] = "RDAP"
        result["status"] = data.get("status", [])

        for nameserver in data.get("nameservers", []):
            name = nameserver.get("ldhName")
            if name:
                result["nameservers"].append(name.rstrip(".").lower())

        for event in data.get("events", []):
            action = event.get("eventAction", "").lower()
            date = event.get("eventDate")

            if action in ("registration", "registered"):
                result["registration_date"] = date
            elif action in ("expiration", "expiry"):
                result["expiration_date"] = date
            elif action in (
                "last changed",
                "last update of rdap database",
            ):
                result["last_updated"] = date

        for entity in data.get("entities", []):
            roles = set(entity.get("roles", []))
            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2 or not isinstance(vcard[1], list):
                continue
            properties = vcard[1]
            if "registrant" in roles:
                for item in properties:
                    if len(item) >= 4 and item[0] == "fn":
                        result["registrant"] = item[3]
                    elif (len(item) >= 4 and item[0] == "adr"
                          and isinstance(item[3], list) and len(item[3]) > 6):
                        result["registrant_country"] = item[3][6] or None
            if "registrar" in roles:
                for item in properties:
                    if len(item) >= 4 and item[0] == "fn":
                        result["registrar"] = item[3]
                    elif (len(item) >= 4 and item[0] == "adr"
                          and isinstance(item[3], list) and len(item[3]) > 6):
                        result["registrar_country"] = item[3][6] or None

        return result

    except requests.Timeout:
        result["error"] = "The registration lookup timed out."
    except requests.RequestException as exc:
        result["error"] = f"Registration request failed: {type(exc).__name__}."
    except (ValueError, TypeError):
        result["error"] = "The registration service returned invalid data."
    except Exception as exc:
        result["error"] = f"Registration lookup failed: {type(exc).__name__}."

    return result


def collect_domain_intelligence(target, resolved_ips=None):
    """Collect DNS and registration details, reusing the scan's validated IP when available."""

    domain = normalize_domain(target)

    validated_ips = []
    for value in resolved_ips or []:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global and str(address) not in validated_ips:
            validated_ips.append(str(address))

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM,
        )

        public_ips = sorted({
            item[4][0]
            for item in addresses
            if ipaddress.ip_address(item[4][0]).is_global
        })

    except socket.gaierror:
        public_ips = []

    # The HTTP scanner pins its request to a validated public address. Reuse it
    # so a transient second DNS lookup does not discard all domain metadata.
    public_ips = sorted(set(public_ips + validated_ips))

    dns_records = query_dns(domain)
    email_security = query_email_security(domain)
    registration = query_registration(domain)
    suffix_info = get_domain_suffix_info(domain)
    first_archived_date = query_first_archived_date(domain)

    return {
        "target": target,
        "domain": domain,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "public_ip_addresses": public_ips,
        "dns_records": dns_records,
        "email_security": email_security,
        "registration": registration,
        **suffix_info,
        "website_first_archived_date": first_archived_date,
        "website_creation_date_note": (
            "The earliest known Wayback Machine HTML capture is an estimate; "
            "the website may have existed earlier."
            if first_archived_date
            else "No archive date is available; a website launch date cannot be confirmed."
        ),
        "limitations": [
            "Registration information may be unavailable or privacy-protected.",
            "The registration date is not necessarily the website launch date.",
            "DNS addresses may belong to a CDN or proxy rather than the origin server.",
            "An empty DNS result does not always mean the record does not exist.",
            "For .lk domains, check the official registry if RDAP data is unavailable.",
        ],
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python domain_intelligence.py https://example.com")
        sys.exit(1)

    try:
        report = collect_domain_intelligence(sys.argv[1])
        print(json.dumps(report, indent=2, ensure_ascii=False))
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        sys.exit(1)
    except Exception as exc:
        print(
            json.dumps(
                {"error": f"Unexpected error: {type(exc).__name__}"},
                indent=2,
            )
        )
        sys.exit(1)
