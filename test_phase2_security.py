
import socket
from threading import Event

import pytest

import scanner


class FakeResponse:
    """A small fake HTTP response for redirect tests."""

    def __init__(self, url, status_code=200, headers=None):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def close(self):
        self.closed = True


def dns_record(ip_address):
    """Build a getaddrinfo-style result for an IP address."""
    address = socket.getaddrinfo(
        ip_address,
        443,
        type=socket.SOCK_STREAM,
    )[0]
    return address


def test_private_ipv4_address_is_blocked():
    with pytest.raises(ValueError):
        scanner.normalize_url("http://127.0.0.1")


def test_private_ipv6_address_is_blocked():
    with pytest.raises(ValueError):
        scanner.normalize_url("http://[::1]")


def test_local_hostname_is_blocked():
    with pytest.raises(ValueError):
        scanner.normalize_url("http://localhost")


def test_hostname_with_mixed_public_and_private_ips_is_blocked(
    monkeypatch,
):
    public_record = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("93.184.216.34", 443),
    )
    private_record = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("192.168.1.10", 443),
    )

    monkeypatch.setattr(
        scanner.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [public_record, private_record],
    )

    with pytest.raises(ValueError, match="private or non-public"):
        scanner._resolve_public_addresses("example.com", 443)


def test_unresolvable_hostname_is_rejected(monkeypatch):
    def fail_dns(*args, **kwargs):
        raise socket.gaierror("Simulated DNS failure")

    monkeypatch.setattr(scanner.socket, "getaddrinfo", fail_dns)

    with pytest.raises(ValueError, match="could not be resolved"):
        scanner._resolve_public_addresses("example.com", 443)


def test_redirect_loop_is_reported_without_connection_error(
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)

    # Keep this test independent of external DNS.
    monkeypatch.setattr(
        scanner,
        "_resolve_public_addresses",
        lambda hostname, port: ["93.184.216.34"],
    )

    start_url = "https://example.com/loop"
    response = FakeResponse(
        url=start_url,
        status_code=302,
        headers={"Location": start_url},
    )

    monkeypatch.setattr(
        scanner,
        "_safe_get",
        lambda url: response,
    )

    report = scanner.scan_website(start_url)

    assert report["status"] == "completed"
    assert report["http_status"] == 302
    assert report["final_url"] == start_url

    finding_titles = [
        finding["title"] for finding in report["findings"]
    ]
    assert "Redirect detected" in finding_titles
    assert "Redirect loop detected" in finding_titles
    assert response.closed


def test_redirect_to_localhost_is_rejected_before_second_request(
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(
        scanner,
        "_resolve_public_addresses",
        lambda hostname, port: ["93.184.216.34"],
    )

    response = FakeResponse(
        url="https://example.com/",
        status_code=302,
        headers={"Location": "http://127.0.0.1/"},
    )

    requested_urls = []

    def fake_get(url):
        requested_urls.append(url)
        return response

    monkeypatch.setattr(scanner, "_safe_get", fake_get)

    with pytest.raises(ValueError):
        scanner.scan_website("https://example.com/")

    assert len(requested_urls) == 1
    assert response.closed


def test_cookie_inspection_reports_missing_attributes_without_values():
    response = FakeResponse(
        "https://example.com",
        headers={"Set-Cookie": "session=do-not-store; Path=/"},
    )
    findings = []
    checks = scanner._inspect_cookie_headers(
        response,
        True,
        lambda severity, title, details: findings.append((severity, title, details)),
    )

    assert checks == [{
        "name": "session",
        "secure": False,
        "http_only": False,
        "same_site": None,
    }]
    assert {item[1].split(":")[0] for item in findings} == {
        "Cookie missing Secure attribute",
        "Cookie missing HttpOnly attribute",
        "Cookie missing SameSite attribute",
    }
    assert all("do-not-store" not in " ".join(item) for item in findings)


def test_page_audit_finds_get_password_form_and_mixed_content():
    response = FakeResponse(
        "https://example.com/login",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    response.body = (
        b'<form><input type="password" name="password"></form>'
        b'<script src="http://cdn.example.test/app.js"></script>'
    )
    findings = []

    summary = scanner._inspect_page_security(
        response,
        lambda severity, title, details: findings.append((severity, title, details)),
    )

    assert summary["html_inspected"] is True
    assert summary["password_forms"] == 1
    assert summary["mixed_content"] == 1
    assert [item[1] for item in findings] == [
        "Password form uses GET",
        "Active mixed content detected",
    ]


def test_safe_page_audit_does_not_flag_relative_secure_form():
    response = FakeResponse(
        "https://example.com/login",
        headers={"Content-Type": "text/html"},
    )
    response.body = (
        b'<form method="post" action="/login"><input type="password"></form>'
        b'<script src="/app.js"></script>'
    )
    findings = []

    summary = scanner._inspect_page_security(
        response,
        lambda severity, title, details: findings.append(title),
    )

    assert summary["password_forms"] == 1
    assert summary["mixed_content"] == 0
    assert findings == []


def test_openapi_document_is_inventoried_without_calling_endpoints():
    response = FakeResponse(
        "https://example.com/openapi.json",
        headers={"Content-Type": "application/json"},
    )
    response.body = b'{"openapi":"3.1.0","info":{"title":"Sample API"},"paths":{"/health":{"get":{}},"/users":{"get":{},"post":{}}}}'

    summary = scanner._inspect_page_security(response, lambda *_: None)

    assert summary["api_spec"]["title"] == "Sample API"
    assert summary["api_spec"]["endpoint_count"] == 2
    assert summary["api_spec"]["paths"][1] == {
        "path": "/users", "methods": ["GET", "POST"]
    }


def test_thorough_scan_checks_each_page_and_respects_robots(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scanner, "_resolve_public_addresses", lambda *_: ["93.184.216.34"])

    root = FakeResponse("https://example.com/", headers={"Content-Type": "text/html"})
    root.body = b'<a href="/about">About</a><a href="/private">Private</a>'
    robots = FakeResponse("https://example.com/robots.txt", headers={})
    robots.body = b"User-agent: *\nDisallow: /private\n"
    about = FakeResponse("https://example.com/about", headers={"Content-Type": "text/html"})
    about.body = b"<form><input type='password'></form>"
    requested = []

    def fake_get(url, **kwargs):
        requested.append(url)
        return {root.url: root, robots.url: robots, about.url: about}[url]

    monkeypatch.setattr(scanner, "_safe_get", fake_get)
    report = scanner.scan_website("https://example.com/", profile="thorough")

    assert requested == [root.url, robots.url, about.url]
    assert len(report["pages"]) == 2
    assert report["pages"][1]["headers_checked"] == 6
    assert any(item["url"].endswith("/private") and "robots.txt" in item["reason"]
               for item in report["pages_skipped"])
    assert any("/about" in item["evidence"] for item in report["findings"])


def test_thorough_crawl_uses_same_origin_sitemap_when_page_has_no_links(monkeypatch):
    monkeypatch.setattr(scanner, "_resolve_public_addresses", lambda *_: ["93.184.216.34"])
    robots = FakeResponse("https://example.com/robots.txt", headers={})
    robots.body = b"User-agent: *\nSitemap: https://example.com/sitemap.xml\n"
    sitemap = FakeResponse("https://example.com/sitemap.xml", headers={"Content-Type": "application/xml"})
    sitemap.body = b"<urlset><url><loc>https://example.com/from-sitemap</loc></url></urlset>"
    page = FakeResponse("https://example.com/from-sitemap", headers={"Content-Type": "text/html"})
    page.body = b"<html></html>"
    requested = []

    def fake_get(url, **_kwargs):
        requested.append(url)
        return {robots.url: robots, sitemap.url: sitemap, page.url: page}[url]

    monkeypatch.setattr(scanner, "_safe_get", fake_get)
    pages, skipped = scanner._crawl_same_origin(
        "https://example.com/", [], None, lambda *_: None
    )

    assert requested == [robots.url, sitemap.url, page.url]
    assert pages[-1]["url"] == page.url
    assert pages[-1]["state"] == "checked"
    assert skipped == []


def test_active_profile_reports_cors_credential_reflection(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scanner, "_resolve_public_addresses", lambda *_: ["93.184.216.34"])
    root = FakeResponse("https://example.com/", headers={})
    probe = FakeResponse("https://example.com/", headers={
        "Access-Control-Allow-Origin": "https://securescan.invalid",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET",
        "Access-Control-Allow-Headers": "Authorization",
    })
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return root if len(calls) == 1 else probe

    monkeypatch.setattr(scanner, "_safe_get", fake_get)
    report = scanner.scan_website("https://example.com/", profile="active")

    assert calls[1][1]["method"] == "OPTIONS"
    assert calls[1][1]["extra_headers"]["Origin"] == "https://securescan.invalid"
    assert "CORS preflight accepts an untrusted origin with credentials" in [item["title"] for item in report["findings"]]
    assert report["active_checks"][0]["status"] == "risk"


def test_cancel_event_stops_scan_before_any_request(monkeypatch):
    event = Event()
    event.set()
    monkeypatch.setattr(scanner, "validate_url", lambda url: url)
    monkeypatch.setattr(scanner, "_safe_get", lambda *_args, **_kwargs: pytest.fail("request should not run"))

    with pytest.raises(scanner.ScanCancelled):
        scanner.scan_website("https://example.com/", cancel_event=event)


def test_cross_domain_redirect_is_not_scanned_without_second_confirmation(
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        scanner,
        "_resolve_public_addresses",
        lambda hostname, port: ["93.184.216.34"],
    )
    response = FakeResponse(
        "https://example.com/",
        status_code=302,
        headers={"Location": "https://other.example/"},
    )
    requested = []
    monkeypatch.setattr(scanner, "_safe_get", lambda url: requested.append(url) or response)

    report = scanner.scan_website("https://example.com/")

    assert len(requested) == 1
    assert report["final_url"] == "https://example.com/"
    assert "Cross-domain redirect not followed" in [
        item["title"] for item in report["findings"]
    ]
