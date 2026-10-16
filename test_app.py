
import json

import pytest
from fastapi.testclient import TestClient

import app as web_app


@pytest.fixture
def client():
    return TestClient(web_app.app)


@pytest.fixture(autouse=True)
def isolate_scan_history(tmp_path, monkeypatch):
    monkeypatch.setattr(web_app, "HISTORY_PATH", tmp_path / "history.sqlite3")
    monkeypatch.setattr(web_app, "SCAN_COOLDOWN_SECONDS", 0)
    web_app.LAST_SCAN_BY_TARGET.clear()


def test_homepage_loads(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "SecureScan" in response.text
    assert "Run security scan" in response.text


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_returns_normalized_report(client, monkeypatch, tmp_path):
    report_path = tmp_path / "scan_report.json"

    monkeypatch.setattr(web_app, "REPORT_PATH", report_path)
    monkeypatch.setattr(
        web_app.scanner,
        "validate_url",
        lambda url: url,
    )

    def fake_scan_website(target, **kwargs):
        report = {
            "target": target,
            "status_code": 200,
            "https": True,
            "findings": [
                "Missing Content-Security-Policy",
                "Missing X-Frame-Options",
            ],
        }
        report_path.write_text(
            json.dumps(report),
            encoding="utf-8",
        )

    monkeypatch.setattr(
        web_app.scanner,
        "scan_website",
        fake_scan_website,
    )
    monkeypatch.setattr(web_app, "collect_intelligence", lambda target, **kwargs: {
        "domain_intelligence": {
            "domain": "example.com",
            "email_security": {"spf_status": "unavailable", "dmarc_status": "unavailable"},
        },
        "tls_intelligence": {},
        "ip_geolocation": {},
        "registration_country": None,
    })

    response = client.post(
        "/api/scan",
        json={"url": "https://example.com", "authorized": True},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["target"] == "https://example.com"
    assert data["status_code"] == 200
    assert data["https"] is True
    assert data["finding_count"] == 2
    assert len(data["findings"]) == 2
    assert data["severity_counts"]["Medium"] == 2


def test_scan_requires_authorization_confirmation(client):
    response = client.post("/api/scan", json={"url": "https://example.com"})

    assert response.status_code == 403
    assert "permission" in response.json()["detail"]


def test_scan_cooldown_prevents_repeated_requests(client, monkeypatch):
    monkeypatch.setattr(web_app.scanner, "validate_url", lambda url: url)
    monkeypatch.setattr(web_app, "SCAN_COOLDOWN_SECONDS", 30)
    web_app.LAST_SCAN_BY_TARGET["example.com"] = web_app.time.monotonic()

    response = client.post(
        "/api/scan",
        json={"url": "https://example.com", "authorized": True},
    )

    assert response.status_code == 429
    assert "recently" in response.json()["detail"]


def test_invalid_url_returns_400(client, monkeypatch):
    def reject_url(url):
        raise ValueError("Invalid URL")

    monkeypatch.setattr(
        web_app.scanner,
        "validate_url",
        reject_url,
    )

    response = client.post(
        "/api/scan",
        json={"url": "not-a-valid-url", "authorized": True},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid URL"


def test_timeout_returns_504(client, monkeypatch):
    monkeypatch.setattr(
        web_app.scanner,
        "validate_url",
        lambda url: url,
    )

    def timeout_scan(target, **kwargs):
        raise web_app.requests.Timeout("Request timed out")

    monkeypatch.setattr(
        web_app.scanner,
        "scan_website",
        timeout_scan,
    )

    response = client.post(
        "/api/scan",
        json={"url": "https://example.com", "authorized": True},
    )

    assert response.status_code == 504
    assert "too long" in response.json()["detail"]


def test_connection_error_returns_502(client, monkeypatch):
    monkeypatch.setattr(
        web_app.scanner,
        "validate_url",
        lambda url: url,
    )

    def failed_scan(target, **kwargs):
        raise web_app.requests.ConnectionError("Connection failed")

    monkeypatch.setattr(
        web_app.scanner,
        "scan_website",
        failed_scan,
    )

    response = client.post(
        "/api/scan",
        json={"url": "https://example.com", "authorized": True},
    )

    assert response.status_code == 502


def test_missing_url_is_rejected(client):
    response = client.post("/api/scan", json={})

    assert response.status_code == 422


def test_missing_report_returns_500(client, monkeypatch, tmp_path):
    monkeypatch.setattr(
        web_app.scanner,
        "validate_url",
        lambda url: url,
    )
    monkeypatch.setattr(
        web_app.scanner,
        "scan_website",
        lambda target, **kwargs: None,
    )
    monkeypatch.setattr(
        web_app,
        "REPORT_PATH",
        tmp_path / "missing_report.json",
    )

    response = client.post(
        "/api/scan",
        json={"url": "https://example.com", "authorized": True},
    )

    assert response.status_code == 500


def test_scan_history_can_be_cleared(client):
    web_app.save_scan_history({
        "target": "https://example.com",
        "scan_time": "2026-10-16T00:00:00+00:00",
        "finding_count": 0,
        "risk_assessment": {"score_percent": 0, "level": "Low"},
        "findings": [],
    })

    assert len(client.get("/api/history").json()["scans"]) == 1
    cleared = client.delete("/api/history")

    assert cleared.status_code == 200
    assert cleared.json()["deleted_count"] == 1
    assert client.get("/api/history").json()["scans"] == []


def test_dns_timeout_is_not_scored_as_missing_policy():
    report = {
        "https": True,
        "domain_intelligence": {
            "email_security": {
                "spf_status": "unavailable",
                "dmarc_status": "unavailable",
            },
        },
    }

    assessment = web_app.calculate_risk_assessment(report)

    assert not any("SPF DNS policy" == item["check"] for item in assessment["checks"])
    assert not any("DMARC DNS policy" == item["check"] for item in assessment["checks"])


def test_failed_tls_connection_is_not_reported_as_invalid_certificate(monkeypatch):
    monkeypatch.setattr(web_app.domain_intelligence, "collect_domain_intelligence", lambda *_args, **_kwargs: {
        "domain": "example.com", "public_ip_addresses": [], "registration": {},
        "dns_records": {}, "email_security": {},
    })
    monkeypatch.setattr(web_app.tls_intelligence, "inspect_tls_certificate", lambda *_args, **_kwargs: {
        "tls_connection_successful": False, "certificate_valid": False,
        "error": "TLS connection timed out.",
    })
    monkeypatch.setattr(web_app, "get_ip_geolocation", lambda _ips: {"ip": None, "error": "No public IP."})

    result = web_app.collect_intelligence("https://example.com")

    assert result["tls_intelligence"]["certificate_valid"] is None
    assert result["tls_intelligence"]["connection_successful"] is False


def test_scan_comparison_reports_new_and_resolved_findings():
    previous = {
        "scan_time": "before",
        "findings": [{"title": "Missing CSP"}, {"title": "Old issue"}],
        "risk_assessment": {"score_percent": 30},
    }
    current = {
        "findings": [{"title": "Missing CSP"}, {"title": "New issue"}],
        "risk_assessment": {"score_percent": 45},
    }

    comparison = web_app.compare_scan_reports(current, previous)

    assert comparison["risk_score_change"] == 15
    assert comparison["new_findings"] == ["New issue"]
    assert comparison["resolved_findings"] == ["Old issue"]
