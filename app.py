
import ipaddress
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
import socket
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock
from typing import Literal

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

import scanner
import domain_intelligence
import tls_intelligence


REPORT_PATH = Path("scan_report.json")
HISTORY_PATH = Path(__file__).with_name("scan_history.sqlite3")
SCAN_LOCK = Lock()
SCAN_STATUS_LOCK = Lock()
SCAN_CANCEL_EVENT = Event()
SCAN_STATUS = {"active": False, "stage": "idle", "message": "Ready to scan.", "completed": 0, "total": 0}
SCAN_COOLDOWN_SECONDS = 15
LAST_SCAN_BY_TARGET = {}

app = FastAPI(
    title="SecureScan",
    description="Website security and domain intelligence scanner",
)


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False
    profile: Literal["quick", "thorough", "active"] = "quick"
    auth_token: str | None = Field(default=None, max_length=4096)


class FindingStateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    finding_id: str = Field(min_length=64, max_length=64)
    state: Literal["open", "fixed", "accepted", "false_positive"]
    reason: str | None = Field(default=None, max_length=500)
    expires_at: str | None = Field(default=None, max_length=40)


def normalize_report(report):
    if not isinstance(report, dict):
        report = {}

    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    normalized_findings = []

    for finding in findings:
        if isinstance(finding, str):
            finding = {
                "title": finding,
                "description": finding,
                "severity": "Medium",
            }
        elif not isinstance(finding, dict):
            continue

        severity = str(finding.get("severity", "Info")).capitalize()
        if severity == "Review":
            severity = "Medium"
        title = str(
            finding.get("title")
            or finding.get("name")
            or "Security finding"
        )
        if severity == "Info":
            severity = inferred_finding_severity(title)
        if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
            severity = "Info"

        evidence = str(finding.get("evidence") or finding.get("details") or finding.get("description") or "Observed during passive scan.")
        finding_id = finding.get("finding_id") or hashlib.sha256(
            (title + "\0" + evidence).encode("utf-8")
        ).hexdigest()
        normalized_findings.append({
            **finding,
            "title": title,
            "description": str(
                finding.get("description")
                or finding.get("details")
                or finding.get("message")
                or ""
            ),
            "severity": severity,
            "evidence": evidence,
            "finding_id": finding_id,
            "confidence": finding.get("confidence") or "Medium",
            "recommendation": finding.get("recommendation")
            or recommendation_for_finding(title),
        })

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for finding in normalized_findings:
        counts[finding["severity"]] += 1

    target = (
        report.get("target")
        or report.get("url")
        or report.get("scanned_url")
        or ""
    )

    return {
        **report,
        "target": target,
        "status": report.get("status", "completed"),
        "status_code": report.get(
            "status_code", report.get("http_status")
        ),
        "https": report.get(
            "https", str(target).lower().startswith("https://")
        ),
        "scan_time": report.get("scan_time")
        or datetime.now(timezone.utc).isoformat(),
        "findings": normalized_findings,
        "finding_count": len(normalized_findings),
        "severity_counts": counts,
    }


SECURITY_HEADER_RISK_POINTS = {
    "Content-Security-Policy": 12,
    "Strict-Transport-Security": 10,
    "X-Content-Type-Options": 8,
    "X-Frame-Options": 8,
    "Referrer-Policy": 4,
    "Permissions-Policy": 3,
}


@contextmanager
def _history_connection():
    connection = sqlite3.connect(HISTORY_PATH)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_key TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT,
            finding_count INTEGER NOT NULL,
            report_json TEXT NOT NULL
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_target ON scan_history(target_key, id DESC)")
        connection.execute("""CREATE TABLE IF NOT EXISTS finding_states (
            target_key TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            state TEXT NOT NULL,
            reason TEXT,
            expires_at TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (target_key, finding_id)
        )""")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _target_key(target):
    from urllib.parse import urlparse
    parsed = urlparse(str(target))
    return (parsed.hostname or str(target)).lower().rstrip(".")


def compare_scan_reports(current, previous):
    if not previous:
        return {"available": False, "message": "This is the first saved scan for this domain."}
    before = {str(item.get("title")) for item in previous.get("findings", []) if isinstance(item, dict)}
    after = {str(item.get("title")) for item in current.get("findings", []) if isinstance(item, dict)}
    old_score = (previous.get("risk_assessment") or {}).get("score_percent", 0)
    new_score = (current.get("risk_assessment") or {}).get("score_percent", 0)
    return {
        "available": True,
        "previous_scan_time": previous.get("scan_time"),
        "previous_risk_score": old_score,
        "current_risk_score": new_score,
        "risk_score_change": new_score - old_score,
        "new_findings": sorted(after - before),
        "resolved_findings": sorted(before - after),
    }


def save_scan_history(report):
    key = _target_key(report.get("target"))
    serialized = json.dumps(report, ensure_ascii=False)
    with _history_connection() as connection:
        connection.execute(
            "INSERT INTO scan_history (target_key,target,scan_time,risk_score,risk_level,finding_count,report_json) VALUES (?,?,?,?,?,?,?)",
            (key, str(report.get("target", "")), str(report.get("scan_time", "")),
             (report.get("risk_assessment") or {}).get("score_percent"),
             (report.get("risk_assessment") or {}).get("level"),
             report.get("finding_count", 0), serialized),
        )
        connection.execute("DELETE FROM scan_history WHERE id NOT IN (SELECT id FROM scan_history ORDER BY id DESC LIMIT 200)")


def get_scan_history(limit=50):
    limit = max(1, min(int(limit), 50))
    with _history_connection() as connection:
        rows = connection.execute("SELECT id,target,scan_time,risk_score,risk_level,finding_count FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]


def apply_finding_states(report):
    target_key = _target_key(report.get("target"))
    now = datetime.now(timezone.utc)
    with _history_connection() as connection:
        rows = connection.execute(
            "SELECT finding_id,state,reason,expires_at FROM finding_states WHERE target_key=?",
            (target_key,),
        ).fetchall()
        for row in rows:
            if row["expires_at"]:
                try:
                    if datetime.fromisoformat(row["expires_at"]) <= now:
                        connection.execute("DELETE FROM finding_states WHERE target_key=? AND finding_id=?", (target_key, row["finding_id"]))
                except ValueError:
                    connection.execute("DELETE FROM finding_states WHERE target_key=? AND finding_id=?", (target_key, row["finding_id"]))
    state_map = {}
    for row in rows:
        if row["expires_at"]:
            try:
                expires = datetime.fromisoformat(row["expires_at"])
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires <= now:
                    continue
            except ValueError:
                continue
        state_map[row["finding_id"]] = row
    for finding in report.get("findings", []):
        override = state_map.get(finding.get("finding_id"))
        finding["workflow_state"] = override["state"] if override else "open"
        finding["state_reason"] = override["reason"] if override else None
        finding["state_expires_at"] = override["expires_at"] if override else None
    return report


def save_finding_state(request):
    normalized_expiry = None
    if request.state == "false_positive" and not (request.reason or "").strip():
        raise ValueError("A reason is required to suppress a finding as a false positive.")
    if request.expires_at:
        try:
            expiry = datetime.fromisoformat(request.expires_at)
        except ValueError as error:
            raise ValueError("Expiry must be an ISO date or timestamp.") from error
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise ValueError("Expiry must be in the future.")
        normalized_expiry = expiry.astimezone(timezone.utc).isoformat()
    if request.state == "open":
        with _history_connection() as connection:
            connection.execute("DELETE FROM finding_states WHERE target_key=? AND finding_id=?", (_target_key(request.target), request.finding_id))
        return
    with _history_connection() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO finding_states (target_key,finding_id,state,reason,expires_at,updated_at) VALUES (?,?,?,?,?,?)",
            (_target_key(request.target), request.finding_id, request.state,
             (request.reason or "").strip() or None, normalized_expiry,
             datetime.now(timezone.utc).isoformat()),
        )


def inferred_finding_severity(title):
    lower_title = title.lower()
    if "http connection" in lower_title or "certificate validation failed" in lower_title:
        return "High"
    if (
        "content-security-policy" in lower_title
        or "strict-transport-security" in lower_title
        or "expires soon" in lower_title
    ):
        return "Medium"
    if lower_title.startswith("missing "):
        return "Low"
    return "Info"


def recommendation_for_finding(title):
    """Return a practical remediation for known passive-scan findings."""
    lower_title = title.lower()
    recommendations = {
        "content-security-policy": (
            "Add a Content-Security-Policy response header and tune its "
            "directives for the resources this site needs."
        ),
        "strict-transport-security": (
            "After confirming HTTPS works for the whole site, add a "
            "Strict-Transport-Security header with an appropriate max-age."
        ),
        "x-content-type-options": (
            "Add X-Content-Type-Options: nosniff to prevent MIME type guessing."
        ),
        "x-frame-options": (
            "Set X-Frame-Options or a frame-ancestors Content-Security-Policy "
            "directive to control embedding."
        ),
        "referrer-policy": (
            "Set a Referrer-Policy that limits referrer information, such as "
            "strict-origin-when-cross-origin."
        ),
        "permissions-policy": (
            "Add a Permissions-Policy header and disable browser features "
            "the site does not use."
        ),
        "http connection": (
            "Configure HTTPS with a valid certificate and redirect HTTP "
            "requests to HTTPS."
        ),
        "cookie missing secure": "Add the Secure attribute so the cookie is sent only over HTTPS.",
        "cookie missing httponly": "Add the HttpOnly attribute unless client-side scripts specifically need to read this cookie.",
        "cookie missing samesite": "Set an explicit SameSite policy such as Lax; use Strict where the site flow permits it.",
        "samesite=none without secure": "Add Secure to this cookie or change its SameSite policy from None.",
        "spf": "Publish and validate an SPF policy in the domain's DNS TXT records to define permitted sending hosts.",
        "dmarc": "Publish a DMARC policy at _dmarc.<domain>, starting with reporting if enforcement is not ready.",
        "password form uses get": "Change the form to POST over HTTPS and ensure the application never places passwords in URL parameters.",
        "password form submits over http": "Change the form action to HTTPS and verify the destination has a valid TLS certificate.",
        "active mixed content": "Serve all scripts, frames, and other executable resources over HTTPS.",
        "technology banner disclosed": "Remove unnecessary product and version details from Server and X-Powered-By response headers.",
    }
    for marker, recommendation in recommendations.items():
        if marker in lower_title:
            return recommendation
    if "certificate" in lower_title:
        return "Renew or correctly configure the TLS certificate, then verify the full certificate chain."
    return None


def calculate_risk_assessment(report):
    """Score only the passive checks this scanner can observe.

    The percentage is a weighted share of observed risk points, not a
    probability of compromise or a measure of every possible vulnerability.
    """
    findings = [
        item for item in (report.get("findings") or [])
        if not isinstance(item, dict) or item.get("workflow_state") != "false_positive"
    ]
    titles = {
        str(item.get("title", "")).lower()
        for item in findings
        if isinstance(item, dict)
    }
    checks = []
    risk_points = 0
    maximum_points = 0

    https = report.get("https")
    if https is not None:
        points = 0 if https else 25
        risk_points += points
        maximum_points += 25
        checks.append({
            "check": "HTTPS transport",
            "status": "pass" if https else "risk",
            "points": points,
            "maximum_points": 25,
            "evidence": (
                "The final URL uses HTTPS."
                if https
                else "The final URL uses unencrypted HTTP."
            ),
        })

    for header, weight in SECURITY_HEADER_RISK_POINTS.items():
        if header == "Strict-Transport-Security" and not https:
            continue
        maximum_points += weight
        matching = [title for title in titles if header.lower() in title]
        issue = any(token in title for title in matching for token in ("missing", "weak", "empty", "misconfigured", "broad", "report-only"))
        points = weight if issue else 0
        risk_points += points
        checks.append({
            "check": header,
            "status": "risk" if issue else "pass",
            "points": points,
            "maximum_points": weight,
            "evidence": (
                "; ".join(title for title in matching)
                if issue
                else "Response header was present."
            ),
        })

    email_security = (report.get("domain_intelligence") or {}).get("email_security")
    if isinstance(email_security, dict):
        for key, label, weight in (("spf_records", "SPF", 4), ("dmarc_records", "DMARC", 4)):
            status_key = "spf_status" if label == "SPF" else "dmarc_status"
            record_status = email_security.get(status_key)
            if record_status not in {"found", "not_found"}:
                continue
            maximum_points += weight
            present = record_status == "found" or bool(email_security.get(key))
            points = 0 if present else weight
            risk_points += points
            checks.append({
                "check": f"{label} DNS policy",
                "status": "pass" if present else "risk",
                "points": points,
                "maximum_points": weight,
                "evidence": "DNS policy record found." if present else "TXT lookup completed, but no matching policy record was found.",
            })

    cookie_checks = report.get("cookie_checks") or []
    for cookie in cookie_checks:
        for attr, label, weight, applies in (
            ("secure", "Secure", 3, bool(https)),
            ("http_only", "HttpOnly", 2, True),
            ("same_site", "SameSite", 2, True),
        ):
            if not applies:
                continue
            maximum_points += weight
            present = bool(cookie.get(attr))
            points = 0 if present else weight
            risk_points += points
            checks.append({
                "check": f"Cookie {label} ({cookie.get('name', 'cookie')})",
                "status": "pass" if present else "risk",
                "points": points,
                "maximum_points": weight,
                "evidence": f"Cookie attributes observed: Secure={cookie.get('secure')}, HttpOnly={cookie.get('http_only')}, SameSite={cookie.get('same_site') or 'not set'}.",
            })

    for title, label, weight in (
        ("password form uses get", "Password form transport", 15),
        ("password form submits over http", "Password form transport", 20),
        ("active mixed content detected", "Active mixed content", 10),
        ("cors preflight accepts an untrusted origin with credentials", "Credentialed CORS policy", 20),
    ):
        if any(title in finding_title for finding_title in titles):
            maximum_points += weight
            risk_points += weight
            checks.append({
                "check": label,
                "status": "risk",
                "points": weight,
                "maximum_points": weight,
                "evidence": next((finding_title for finding_title in titles if title in finding_title), label + " issue observed."),
            })

    tls = report.get("tls_intelligence") or {}
    tls_error = str(tls.get("error") or "")
    tls_connected = tls.get("connection_successful")
    cert_valid = tls.get("certificate_valid")
    cert_failure_confirmed = "certificate verification failed" in tls_error.lower()
    if https and (tls_connected is True or cert_failure_confirmed):
        maximum_points += 20
        cert_risk = cert_valid is False or cert_failure_confirmed
        cert_points = 20 if cert_risk else 0
        risk_points += cert_points
        checks.append({
            "check": "TLS certificate validation",
            "status": "risk" if cert_risk else "pass",
            "points": cert_points,
            "maximum_points": 20,
            "evidence": (
                tls_error
                if cert_risk and tls_error
                else "The certificate chain and hostname were verified."
            ),
        })

        days_remaining = tls.get("days_remaining")
        if isinstance(days_remaining, (int, float)):
            expiry_points = (
                10 if days_remaining <= 14
                else 5 if days_remaining <= 30
                else 0
            )
            risk_points += expiry_points
            maximum_points += 10
            checks.append({
                "check": "TLS certificate expiry",
                "status": "risk" if expiry_points else "pass",
                "points": expiry_points,
                "maximum_points": 10,
                "evidence": f"{days_remaining} days remaining.",
            })

    score = round(100 * risk_points / maximum_points) if maximum_points else 0
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Moderate"
    elif score >= 20:
        level = "Guarded"
    else:
        level = "Low"

    return {
        "score_percent": score,
        "level": level,
        "risk_points": risk_points,
        "maximum_points": maximum_points,
        "checks_evaluated": len(checks),
        "checks_with_risk": sum(check["status"] == "risk" for check in checks),
        "checks": checks,
        "method": (
            "Weighted score from observed HTTPS, response security headers, "
            "verified TLS certificate, email DNS policy, cookie attributes, and passive HTML checks."
        ),
        "limitation": (
            "This is not the probability of compromise. SecureScan performs "
            "limited passive checks and cannot confirm the absence of "
            "vulnerabilities in application code, authentication, or data handling."
        ),
    }


def get_registration_country(domain):
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=6,
            headers={"Accept": "application/rdap+json"},
        )
        response.raise_for_status()
        data = response.json()

        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2 or not isinstance(vcard[1], list):
                continue

            for item in vcard[1]:
                if (
                    len(item) >= 4
                    and item[0] == "adr"
                    and isinstance(item[3], list)
                ):
                    address = item[3]
                    if len(address) > 6 and address[6]:
                        return address[6]

    except (
        requests.RequestException,
        ValueError,
        TypeError,
    ):
        pass

    return None


def get_ip_geolocation(ips):
    attempted = False
    for ip in ips:
        try:
            parsed_ip = ipaddress.ip_address(ip)
            if not parsed_ip.is_global:
                continue
            attempted = True

            response = requests.get(
                f"https://ipwho.is/{ip}",
                timeout=6,
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("success", False):
                continue

            connection = data.get("connection") or {}

            return {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": connection.get("isp"),
                "organization": connection.get("org"),
                "asn": connection.get("asn"),
                "location_type": "Approximate IP-based location",
                "source": "ipwho.is",
                "error": None,
            }

        except (
            ValueError,
            requests.RequestException,
            TypeError,
        ):
            continue

    return {
        "ip": None,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "organization": None,
        "asn": None,
        "location_type": "Unavailable",
        "source": "ipwho.is",
        "error": (
            "The IP location lookup did not return a usable result."
            if attempted else "No public IP address was available for the location lookup."
        ),
    }


def collect_intelligence(target, progress_callback=None, resolved_ips=None):
    result = {
        "domain_intelligence": {},
        "tls_intelligence": {},
        "ip_geolocation": {},
        "registration_country": None,
        "intelligence_errors": [],
    }

    domain_data = {}

    try:
        if progress_callback:
            progress_callback("dns", "Checking DNS, email policy, registration and archive data", 0, 1)
        raw_domain = domain_intelligence.collect_domain_intelligence(
            target, resolved_ips=resolved_ips
        )

        if not isinstance(raw_domain, dict):
            raw_domain = {}

        registration = raw_domain.get("registration") or {}
        dns_records = raw_domain.get("dns_records") or {}

        domain_data = {
            **raw_domain,
            "domain": raw_domain.get("domain")
            or raw_domain.get("hostname"),
            "top_level_domain": raw_domain.get("top_level_domain"),
            "country_code_domain": raw_domain.get("country_code_domain"),
            "website_first_archived_date": raw_domain.get(
                "website_first_archived_date"
            ),
            "website_creation_date_note": raw_domain.get(
                "website_creation_date_note"
            ),
            "ip_addresses": (
                raw_domain.get("public_ip_addresses")
                or raw_domain.get("ip_addresses")
                or raw_domain.get("ips")
                or []
            ),
            "dns": dns_records,
            "registrant": registration.get("registrant"),
            "registrant_country": registration.get("registrant_country"),
            "registrar": registration.get("registrar"),
            "registrar_country": registration.get("registrar_country"),
            "registration_date": registration.get(
                "registration_date"
            ),
            "expiration_date": registration.get("expiration_date"),
            "last_updated": registration.get("last_updated"),
            "status": registration.get("status", []),
            "nameservers": registration.get("nameservers")
            or dns_records.get("NS", []),
            "registration_available": registration.get(
                "available", False
            ),
            "registration_error": registration.get("error"),
            "lookup_url": registration.get("lookup_url"),
            "registration_source": registration.get("source"),
        }

        result["domain_intelligence"] = domain_data
        result["registration_country"] = registration.get("registrant_country")

        email_security = raw_domain.get("email_security") or {}
        if email_security.get("spf_status") == "not_found":
            result.setdefault("email_security_findings", []).append({
                "severity": "Medium", "title": "SPF record not found",
                "details": "The domain apex TXT lookup completed, but no SPF record was present.",
                "recommendation": recommendation_for_finding("SPF record not found"),
                "confidence": "High",
            })
        if email_security.get("dmarc_status") == "not_found":
            result.setdefault("email_security_findings", []).append({
                "severity": "Medium", "title": "DMARC record not found",
                "details": "The _dmarc TXT lookup completed, but no DMARC record was present.",
                "recommendation": recommendation_for_finding("DMARC record not found"),
                "confidence": "High",
            })

        if registration.get("error"):
            result["intelligence_errors"].append(
                "Domain registration lookup: "
                + str(registration["error"])
            )

    except scanner.ScanCancelled:
        raise
    except Exception as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        result["intelligence_errors"].append(f"Domain intelligence: {detail}")

    try:
        if progress_callback:
            progress_callback("tls", "Inspecting the TLS certificate", 0, 1)
        raw_tls = tls_intelligence.inspect_tls_certificate(
            target, resolved_ips=resolved_ips
        )

        if not isinstance(raw_tls, dict):
            raw_tls = {}

        result["tls_intelligence"] = {
            **raw_tls,
            "subject": raw_tls.get("certificate_subject"),
            "issuer": raw_tls.get("certificate_issuer"),
            "valid_from": raw_tls.get("valid_from_utc"),
            "valid_until": raw_tls.get("valid_until_utc"),
            "days_remaining": raw_tls.get(
                "days_until_expiration"
            ),
            "version": raw_tls.get("certificate_version"),
            "serial_number": raw_tls.get("serial_number"),
            "subject_alt_names": raw_tls.get(
                "subject_alternative_names", []
            ),
            "tls_version": raw_tls.get("tls_version"),
            "cipher": raw_tls.get("cipher"),
            "certificate_valid": (
                raw_tls.get("certificate_valid")
                if raw_tls.get("tls_connection_successful") is True
                else None
            ),
            "connection_successful": raw_tls.get(
                "tls_connection_successful"
            ),
            "error": raw_tls.get("error"),
        }

        if raw_tls.get("error"):
            result["intelligence_errors"].append(
                "TLS inspection: " + str(raw_tls["error"])
            )

    except scanner.ScanCancelled:
        raise
    except Exception as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        result["intelligence_errors"].append(f"TLS inspection: {detail}")

    ips = domain_data.get("ip_addresses", [])
    if isinstance(ips, str):
        ips = [ips]
    if not isinstance(ips, list):
        ips = []

    if progress_callback:
        progress_callback("location", "Checking approximate public IP location", 0, 1)
    result["ip_geolocation"] = get_ip_geolocation(ips)
    if result["ip_geolocation"].get("error"):
        result["intelligence_errors"].append(
            "IP geolocation: " + result["ip_geolocation"]["error"]
        )
    result["checked_at_utc"] = datetime.now(timezone.utc).isoformat()

    return result


@app.get("/", response_class=HTMLResponse)
def homepage():
    return PAGE


def _update_scan_status(stage=None, message=None, completed=None, total=None, active=None):
    with SCAN_STATUS_LOCK:
        if stage is not None:
            SCAN_STATUS["stage"] = stage
        if message is not None:
            SCAN_STATUS["message"] = message
        if completed is not None:
            SCAN_STATUS["completed"] = completed
        if total is not None:
            SCAN_STATUS["total"] = total
        if active is not None:
            SCAN_STATUS["active"] = active


def build_coverage(report):
    domain = report.get("domain_intelligence") or {}
    registration = domain.get("registration_available")
    tls = report.get("tls_intelligence") or {}
    email = domain.get("email_security") or {}
    dns_notes = (domain.get("dns") or {}).get("_notes") or []
    page = report.get("page_checks") or {}
    checked_at = report.get("scan_time")
    domain_checked = domain.get("checked_at_utc") or checked_at
    crawl_status = "not_selected"
    if report.get("scan_profile") == "thorough":
        crawl_status = "partial" if report.get("pages_skipped") else "complete"
    return [
        {"check": "HTTP headers and cookies", "status": "complete", "source": "Target response", "checked_at": checked_at},
        {"check": "HTML", "status": "complete" if page.get("html_inspected") else "unavailable", "source": "Final page response; max 256 KB", "checked_at": checked_at},
        {"check": "Same-origin page crawl", "status": crawl_status, "source": "Same origin, robots.txt and declared sitemaps", "checked_at": checked_at},
        {"check": "CORS preflight", "status": next((item.get("status") for item in (report.get("active_checks") or []) if item.get("check") == "CORS preflight"), "not_selected"), "source": "One HTTPS OPTIONS request using a synthetic origin", "checked_at": checked_at},
        {"check": "TLS certificate", "status": "complete" if tls.get("connection_successful") else "unavailable", "source": "TLS handshake", "checked_at": tls.get("checked_at_utc") or checked_at},
        {"check": "DNS records", "status": "partial" if dns_notes else "complete", "source": "Configured DNS resolver", "checked_at": domain_checked},
        {"check": "SPF", "status": email.get("spf_status", "unavailable"), "source": "Domain apex TXT record", "checked_at": domain_checked},
        {"check": "DMARC", "status": email.get("dmarc_status", "unavailable"), "source": "_dmarc TXT record", "checked_at": domain_checked},
        {"check": "DKIM", "status": "partial" if email.get("dkim_records") else "common_selectors_only", "source": ", ".join(email.get("dkim_selectors_checked") or []) or "Common selector list", "checked_at": domain_checked},
        {"check": "Registration", "status": "complete" if registration else "unavailable", "source": domain.get("registration_source") or "RDAP", "checked_at": domain_checked},
        {"check": "IP geolocation", "status": "complete" if (report.get("ip_geolocation") or {}).get("ip") else "unavailable", "source": "Approximate public IP lookup", "checked_at": result_checked_at(report)},
    ]


def result_checked_at(report):
    return report.get("checked_at_utc") or report.get("scan_time")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def run_scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(
            status_code=403,
            detail="Confirm that you own this website or have permission to assess it.",
        )
    if not SCAN_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Another scan is already running. Please try again shortly.",
        )

    try:
        SCAN_CANCEL_EVENT.clear()
        target = scanner.validate_url(request.url)
        if request.auth_token and not target.lower().startswith("https://"):
            raise HTTPException(status_code=400, detail="Authentication tokens require an HTTPS target.")
        target_key = _target_key(target)
        now = time.monotonic()
        last_scan = LAST_SCAN_BY_TARGET.get(target_key)
        if last_scan is not None and now - last_scan < SCAN_COOLDOWN_SECONDS:
            wait_seconds = max(1, int(SCAN_COOLDOWN_SECONDS - (now - last_scan)))
            raise HTTPException(
                status_code=429,
                detail=f"This target was scanned recently. Try again in about {wait_seconds} seconds.",
            )
        LAST_SCAN_BY_TARGET[target_key] = now
        _update_scan_status(active=True, stage="starting", message="Preparing the scan", completed=0, total=1)
        def scan_progress(stage=None, message=None, completed=None, total=None):
            if SCAN_CANCEL_EVENT.is_set():
                raise scanner.ScanCancelled("Scan cancelled by the user.")
            _update_scan_status(stage=stage, message=message, completed=completed, total=total)

        scanner.scan_website(
            target, profile=request.profile, auth_token=request.auth_token,
            progress_callback=scan_progress,
            cancel_event=SCAN_CANCEL_EVENT,
        )

        if not REPORT_PATH.exists():
            raise HTTPException(
                status_code=500,
                detail="The scanner did not generate scan_report.json.",
            )

        try:
            with REPORT_PATH.open("r", encoding="utf-8") as file:
                raw_report = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=500,
                detail="The scan report could not be read.",
            ) from exc

        report = normalize_report(raw_report)
        report["target"] = target

        # Use the final URL when the scanner has followed redirects.
        final_url = report.get("final_url") or target
        report["https"] = final_url.lower().startswith("https://")

        _update_scan_status(stage="intelligence", message="Checking DNS, registration and TLS details", completed=0, total=1)
        report.update(collect_intelligence(
            target,
            progress_callback=scan_progress,
            resolved_ips=[report.get("server_ip")] if report.get("server_ip") else [],
        ))
        if SCAN_CANCEL_EVENT.is_set():
            raise scanner.ScanCancelled("Scan cancelled by the user.")

        report["findings"].extend(report.pop("email_security_findings", []))

        tls = report.get("tls_intelligence") or {}
        tls_error = str(tls.get("error") or "")
        certificate_failed = (
            tls.get("connection_successful") is True
            and tls.get("certificate_valid") is False
        ) or "certificate verification failed" in tls_error.lower()
        if certificate_failed:
            report["findings"].append({
                "severity": "High",
                "title": "TLS certificate validation failed",
                "description": tls_error or (
                    "The certificate could not be validated by the scanner."
                ),
                "evidence": tls_error or "Certificate validation reported a failure.",
                "confidence": "High",
                "recommendation": recommendation_for_finding(
                    "TLS certificate validation failed"
                ),
            })
        elif (
            tls.get("connection_successful") is True
            and isinstance(tls.get("days_remaining"), (int, float))
            and tls["days_remaining"] <= 30
        ):
            report["findings"].append({
                "severity": "Medium",
                "title": "TLS certificate expires soon",
                "description": (
                    f"The certificate has {tls['days_remaining']} days remaining."
                ),
                "evidence": f"TLS inspection reports {tls['days_remaining']} days remaining.",
                "confidence": "High",
                "recommendation": recommendation_for_finding(
                    "TLS certificate expires soon"
                ),
            })

        report = normalize_report(report)
        report = apply_finding_states(report)
        report["coverage"] = build_coverage(report)
        report["risk_assessment"] = calculate_risk_assessment(report)
        with _history_connection() as connection:
            previous_row = connection.execute(
                "SELECT report_json FROM scan_history WHERE target_key=? ORDER BY id DESC LIMIT 1",
                (_target_key(report["target"]),),
            ).fetchone()
        previous = json.loads(previous_row["report_json"]) if previous_row else None
        if previous:
            previous = apply_finding_states(previous)
            fixed_before = {
                item.get("finding_id"): item
                for item in previous.get("findings", [])
                if item.get("workflow_state") == "fixed"
            }
            current_ids = {item.get("finding_id") for item in report.get("findings", [])}
            report["fix_verification"] = [
                {
                    "finding_id": finding_id,
                    "title": item.get("title"),
                    "status": "still_detected" if finding_id in current_ids else "not_seen_in_this_scan",
                    "scan_profile": report.get("scan_profile", "quick"),
                }
                for finding_id, item in fixed_before.items()
            ]
        else:
            report["fix_verification"] = []
        report["comparison"] = compare_scan_reports(report, previous)
        save_scan_history(report)
        return report

    except HTTPException:
        _update_scan_status(active=False, stage="error", message="Scan stopped.")
        raise

    except scanner.ScanCancelled as exc:
        _update_scan_status(active=False, stage="cancelled", message="Scan cancelled.")
        raise HTTPException(status_code=409, detail="Scan cancelled.") from exc

    except ValueError as exc:
        _update_scan_status(active=False, stage="error", message=str(exc))
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except (TimeoutError, socket.timeout, requests.Timeout) as exc:
        _update_scan_status(active=False, stage="error", message="Scan timed out.")
        raise HTTPException(
            status_code=504,
            detail="The scan took too long and timed out. Please try again.",
        ) from exc

    except requests.RequestException as exc:
        _update_scan_status(active=False, stage="error", message="A network connection failed.")
        raise HTTPException(
            status_code=502,
            detail="A network connection failed during the scan.",
        ) from exc

    finally:
        if SCAN_STATUS.get("active"):
            _update_scan_status(active=False, stage="complete", message="Scan complete.")
        SCAN_LOCK.release()


@app.get("/api/scan/status")
def scan_progress():
    with SCAN_STATUS_LOCK:
        return dict(SCAN_STATUS)


@app.post("/api/scan/cancel")
def cancel_scan():
    with SCAN_STATUS_LOCK:
        if not SCAN_STATUS.get("active"):
            raise HTTPException(status_code=409, detail="No scan is currently running.")
    SCAN_CANCEL_EVENT.set()
    return {"cancel_requested": True}


@app.get("/api/history")
def scan_history(target: str = "", severity: str = "", state: str = ""):
    scans = get_scan_history(200)
    filtered = []
    for scan in scans:
        if target and target.lower() not in scan["target"].lower():
            continue
        with _history_connection() as connection:
            row = connection.execute("SELECT report_json FROM scan_history WHERE id=?", (scan["id"],)).fetchone()
        report = apply_finding_states(json.loads(row["report_json"])) if row else {}
        if severity and not any(item.get("severity", "").lower() == severity.lower() for item in report.get("findings", [])):
            continue
        if state and not any(item.get("workflow_state", "open") == state for item in report.get("findings", [])):
            continue
        filtered.append(scan)
    return {"scans": filtered, "retention_limit": 200, "storage": "local SQLite database"}


@app.delete("/api/history")
def clear_scan_history():
    with _history_connection() as connection:
        deleted = connection.execute("DELETE FROM scan_history").rowcount
    return {"deleted_count": deleted}


@app.get("/api/history/export")
def export_scan_history():
    with _history_connection() as connection:
        rows = connection.execute("SELECT report_json FROM scan_history ORDER BY id DESC LIMIT 200").fetchall()
    return {"scans": [json.loads(row["report_json"]) for row in rows]}


@app.delete("/api/history/{scan_id}")
def delete_scan_history_entry(scan_id: int):
    with _history_connection() as connection:
        deleted = connection.execute("DELETE FROM scan_history WHERE id=?", (scan_id,)).rowcount
    if not deleted:
        raise HTTPException(status_code=404, detail="Saved scan was not found.")
    return {"deleted": True}


@app.get("/api/history/{scan_id}")
def scan_history_detail(scan_id: int):
    with _history_connection() as connection:
        row = connection.execute("SELECT report_json FROM scan_history WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Saved scan was not found.")
    return apply_finding_states(json.loads(row["report_json"]))


@app.put("/api/findings/state")
def update_finding_state(request: FindingStateRequest):
    try:
        save_finding_state(request)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"updated": True, "state": request.state}


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#070b14">
<title>SecureScan | Website Intelligence</title>
<style>
:root {
  color-scheme: dark;
  --bg:#0b1220; --surface:#111c2e; --surface-raised:#16243a;
  --line:#263953; --text:#edf3fc; --muted:#9aabc0;
  --accent:#41d9bd; --accent-strong:#22bea4; --blue:#79aafc;
  --red:#ff778a; --amber:#f4c36c; --green:#6fd6a8;
}
* { box-sizing:border-box; }
html { scroll-behavior:smooth; }
body {
  margin:0; min-height:100vh; color:var(--text);
  background:
    radial-gradient(ellipse at 82% -12%,rgba(51,105,161,.18),transparent 36%),
    radial-gradient(ellipse at 8% 20%,rgba(36,147,133,.07),transparent 30%),
    var(--bg);
  font:15px/1.55 Inter,"Segoe UI",system-ui,-apple-system,sans-serif;
}
header {
  position:sticky; top:0; z-index:5; border-bottom:1px solid rgba(55,76,104,.55);
  background:rgba(10,17,30,.88); backdrop-filter:blur(18px);
}
.nav,main { max-width:1320px; margin:auto; padding:0 32px; }
.nav { min-height:72px; display:flex; justify-content:space-between; align-items:center; gap:20px; }
.brand { display:flex; align-items:center; gap:11px; color:var(--text); font-size:20px; font-weight:750; letter-spacing:-.4px; text-decoration:none; }
.brand-mark { width:34px; height:34px; display:grid; place-items:center; border:1px solid rgba(65,217,189,.35); border-radius:11px; color:var(--accent); background:rgba(65,217,189,.1); }
.brand-mark svg { width:19px; height:19px; }
.brand span,.accent { color:var(--accent); }
.brand > span:last-child { color:var(--text); }
.brand > span:last-child span { color:var(--accent); }
.sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
.nav-right { display:flex; align-items:center; gap:24px; }
.nav-links { display:flex; gap:22px; }
.nav-links a { color:#b6c4d7; text-decoration:none; font-size:13px; transition:color .18s ease; }
.nav-links a:hover { color:var(--accent); }
.status { display:flex; align-items:center; gap:8px; padding:7px 11px; border:1px solid #2a4c4c; border-radius:999px; color:#9ae5d7; background:rgba(35,105,94,.17); font-size:10px; font-weight:700; letter-spacing:.08em; }
.status-dot { width:7px; height:7px; border-radius:50%; background:var(--accent); box-shadow:0 0 12px rgba(65,217,189,.7); }
main { padding-top:34px; padding-bottom:38px; }
h1 { max-width:760px; font-size:clamp(34px,5vw,54px); line-height:1.08; letter-spacing:-1.8px; margin:10px 0 14px; }
p { color:var(--muted); }
.hero { display:flex; justify-content:space-between; align-items:flex-end; gap:28px; padding:8px 0 28px; }
.eyebrow { display:flex; align-items:center; gap:9px; color:var(--accent); font-size:11px; font-weight:750; letter-spacing:.13em; text-transform:uppercase; }
.hero-copy { max-width:740px; margin:0; font-size:16px; }
.hero-note { display:flex; align-items:center; gap:9px; padding:11px 14px; border:1px solid var(--line); border-radius:12px; background:rgba(17,28,46,.75); color:#c2cedd; font-size:12px; white-space:nowrap; }
.hero-note svg { width:17px; height:17px; color:var(--accent); }
.panel {
  background:linear-gradient(145deg,rgba(20,33,53,.96),rgba(15,25,41,.96));
  border:1px solid rgba(50,70,96,.8); border-radius:17px;
  padding:22px; min-width:0; box-shadow:0 10px 30px rgba(0,0,0,.12);
}
.scan-panel { padding:22px 24px 18px; margin-bottom:20px; background:linear-gradient(115deg,rgba(21,39,58,.98),rgba(16,29,47,.98)); }
.scan-heading { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:15px; }
.scan-heading h2 { margin:0 0 3px; }
.scan-heading p { margin:0; font-size:13px; }
.scan-form { display:flex; gap:12px; }
#cancelScanButton[hidden] { display:none; }
.scan-options { display:grid; grid-template-columns:minmax(170px,.7fr) minmax(220px,1.3fr); gap:12px; margin-top:12px; }
.field { min-width:0; }
.field label { display:block; margin-bottom:5px; color:#a9bad0; font-size:11px; font-weight:700; }
.field input,.field select { width:100%; border:1px solid #354b67; border-radius:10px; padding:10px 12px; color:var(--text); background:#0c1626; font:inherit; }
.field small { display:block; color:var(--muted); margin-top:4px; font-size:10px; }
.progress-wrap { display:none; margin-top:14px; }
.progress-wrap.active { display:block; }
.progress-track { height:7px; overflow:hidden; border-radius:9px; background:#26364d; }
.progress-track span { display:block; width:8%; height:100%; border-radius:inherit; background:var(--accent); transition:width .25s ease; }
.tool-row { display:flex; flex-wrap:wrap; align-items:end; gap:10px; margin:12px 0; }
.tool-row .field { flex:1; min-width:140px; }
.tool-row button { min-height:40px; padding:0 13px; }
.finding-controls { margin:10px 0 15px; }
.finding-controls select { min-height:42px; border:1px solid #354b67; border-radius:10px; background:#0c1626; color:var(--text); padding:0 10px; font:inherit; }
.finding-state { display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin-top:11px; padding-top:10px; border-top:1px solid var(--line); }
.finding-state select,.finding-state input { min-height:36px; border:1px solid #354b67; border-radius:8px; padding:6px 9px; background:#0c1626; color:var(--text); font:inherit; }
.finding-state button { min-height:36px; padding:0 12px; }
.input-wrap { flex:1; min-width:0; display:flex; align-items:center; gap:11px; padding:0 14px; border:1px solid #354b67; border-radius:12px; background:#0c1626; transition:border-color .18s ease,box-shadow .18s ease; }
.input-wrap:focus-within { border-color:var(--accent-strong); box-shadow:0 0 0 3px rgba(65,217,189,.12); }
.input-wrap svg { flex:none; width:18px; height:18px; color:#8da3bd; }
input {
  width:100%; min-width:0; border:0; outline:0; background:transparent;
  color:var(--text); padding:15px 0; font:inherit; font-size:15px;
}
input::placeholder { color:#71839b; }
input[type="checkbox"] { width:16px; height:16px; flex:none; margin:2px 0 0; accent-color:var(--accent); }
button {
  display:inline-flex; justify-content:center; align-items:center; gap:9px;
  background:linear-gradient(135deg,#54e4c6,#2bc5aa); color:#08211f;
  border:0; border-radius:12px; padding:0 20px; min-height:51px;
  font:inherit; font-weight:750; cursor:pointer; box-shadow:0 6px 18px rgba(39,195,167,.17);
  transition:transform .18s ease,filter .18s ease,box-shadow .18s ease;
}
button:hover:not(:disabled) { transform:translateY(-1px); filter:brightness(1.05); box-shadow:0 9px 22px rgba(39,195,167,.24); }
button:disabled { opacity:.62; cursor:wait; box-shadow:none; }
.scan-form button:disabled:after { content:""; width:14px; height:14px; border:2px solid rgba(8,33,31,.35); border-top-color:#08211f; border-radius:50%; animation:spin .8s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }
button:focus-visible,a:focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
.button-icon { width:17px; height:17px; }
.secondary { background:#17263b; color:var(--text); border:1px solid #344a67; box-shadow:none; }
.scan-meta { display:flex; justify-content:space-between; gap:14px; margin-top:12px; font-size:12px; }
.scan-meta p { margin:0; }
.scan-meta .permission { display:flex; align-items:center; gap:7px; }
.scan-meta svg { width:14px; height:14px; color:var(--accent); }
.grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:14px; margin-bottom:20px; }
.metric-card { position:relative; padding:17px 18px; overflow:hidden; }
.metric-card:after { content:""; position:absolute; width:76px; height:76px; right:-30px; bottom:-40px; border-radius:50%; background:rgba(85,142,198,.08); }
.metric-card.primary-metric { border-color:rgba(65,217,189,.33); background:linear-gradient(145deg,rgba(23,57,60,.9),rgba(16,31,47,.96)); }
.two { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; margin:16px 0; }
.content-grid { display:grid; grid-template-columns:minmax(0,1.1fr) minmax(0,.9fr); gap:16px; margin:16px 0; align-items:start; }
.metric { font-size:29px; font-weight:750; line-height:1.2; letter-spacing:-.6px; overflow-wrap:anywhere; margin-top:9px; }
.label { color:var(--muted); font-size:10px; font-weight:750; text-transform:uppercase; letter-spacing:1.15px; }
h2 { font-size:17px; line-height:1.35; letter-spacing:-.2px; margin:0 0 15px; }
h3 { font-size:14px; margin:3px 0 7px; }
.section-title { display:flex; justify-content:space-between; align-items:center; gap:14px; margin-bottom:15px; }
.section-title h2 { margin:0; }
.section-kicker { color:var(--muted); font-size:11px; }
table { width:100%; border-collapse:collapse; overflow-wrap:anywhere; }
td,th { text-align:left; padding:10px 9px; border-bottom:1px solid rgba(50,70,96,.62); vertical-align:top; font-size:13px; }
tr:last-child td { border-bottom:0; }
td:first-child { color:#a9bad0; width:36%; text-transform:capitalize; }
td:last-child { color:#e0e8f2; }
td ul { margin:0; padding-left:18px; }
td li { margin:2px 0; }
pre {
  white-space:pre-wrap; overflow-wrap:anywhere; background:#0b1422;
  border:1px solid var(--line); padding:15px; border-radius:11px;
  color:#c8d8ea; max-height:420px; overflow:auto; font-size:12px;
}
.finding {
  padding:14px 15px; margin:10px 0; border:1px solid rgba(50,70,96,.72);
  border-radius:12px; background:rgba(10,19,33,.68);
}
.finding h3 { display:inline-block; margin-left:9px; }
.finding p { margin:9px 0 0; font-size:12px; }
.severity { display:inline-flex; align-items:center; border-radius:999px; padding:4px 8px; font-weight:800; font-size:10px; letter-spacing:.06em; text-transform:uppercase; background:rgba(121,170,252,.1); color:#a9c7fa; }
.high,.critical { color:var(--red); background:rgba(255,119,138,.12); }
.risk { color:var(--red); background:rgba(255,119,138,.12); }
.medium { color:var(--amber); background:rgba(244,195,108,.12); }
.low,.info { color:var(--accent); background:rgba(65,217,189,.1); }
.guarded { color:#e0c978; }
.risk-meter { width:100%; height:12px; margin:8px 0 3px; accent-color:var(--accent); }
.risk-meter[data-level="Guarded"],.risk-meter[data-level="Moderate"] { accent-color:var(--amber); }
.risk-meter[data-level="High"],.risk-meter[data-level="Critical"] { accent-color:var(--red); }
.risk-summary { display:grid; grid-template-columns:minmax(110px,.3fr) minmax(0,1fr); gap:20px; align-items:center; padding:16px; border:1px solid rgba(50,70,96,.72); border-radius:13px; background:rgba(10,19,33,.6); }
.risk-number { font-size:37px; font-weight:800; line-height:1.1; letter-spacing:-1.4px; }
.risk-number small { font-size:14px; color:var(--muted); font-weight:600; letter-spacing:0; }
.risk-summary p { margin:6px 0 0; font-size:12px; }
.risk-checks { margin-top:13px; }
.risk-checks .finding:first-child { margin-top:0; }
.risk-limit { margin:14px 0 0; padding:11px 13px; border-left:2px solid var(--blue); background:rgba(121,170,252,.06); font-size:12px; }
.empty-state { padding:26px 16px; border:1px dashed #344a67; border-radius:12px; color:var(--muted); text-align:center; }
.empty-icon { width:36px; height:36px; display:grid; place-items:center; margin:0 auto 10px; border-radius:12px; color:var(--accent); background:rgba(65,217,189,.09); }
.empty-icon svg { width:18px; height:18px; }
.dns-records td:first-child { width:70px; font-weight:750; color:var(--accent); }
.report-details { margin-top:16px; }
.report-details summary { display:flex; align-items:center; justify-content:space-between; cursor:pointer; list-style:none; }
.report-details summary::-webkit-details-marker { display:none; }
.report-details summary:after { content:"+"; color:var(--accent); font-size:20px; }
.report-details[open] summary:after { content:"−"; }
.report-details summary h2 { margin:0; }
.report-details p { font-size:13px; }
.muted { color:var(--muted); }
main > .panel { margin:16px 0; }
#message { min-height:20px; margin:0; }
a { color:var(--accent); }
footer { border-top:1px solid rgba(55,76,104,.45); color:var(--muted); text-align:center; padding:22px 24px; font-size:11px; }
@media print {
  :root { color-scheme:light; --bg:#fff; --surface:#fff; --surface-raised:#fff; --line:#cbd5e1; --text:#111827; --muted:#475569; --accent:#0f766e; }
  body { color:#111827; background:#fff; font-size:10pt; }
  header,.hero-note,#scan,.nav-links,.status,footer,.report-details,#downloadButton,.print-button,.tool-row,.finding-state,#history-list { display:none !important; }
  .nav,main { max-width:none; padding:0; }
  main { padding-top:0; }
  .panel,.metric-card { color:#111827; background:#fff !important; border:1px solid #cbd5e1; box-shadow:none; break-inside:avoid; }
  .grid { grid-template-columns:repeat(5,1fr); gap:6px; }
  .content-grid,.two { gap:8px; }
  .finding { background:#fff; border-color:#cbd5e1; break-inside:avoid; }
  p,td,th,.label,.section-kicker,.muted { color:#334155 !important; }
  .severity { border:1px solid currentColor; }
  a { color:#0f766e; }
}
@media(max-width:1000px) {
  .grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .content-grid { grid-template-columns:1fr; }
}
@media(max-width:700px) {
  .nav,main { padding-left:18px; padding-right:18px; }
  .nav { min-height:64px; }
  .nav-links { display:none; }
  main { padding-top:24px; }
  .hero { display:block; padding-top:0; }
  .hero-note { display:inline-flex; margin-top:16px; }
  .grid { grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
  .metric-card { padding:14px; }
  .metric { font-size:24px; }
  .two { grid-template-columns:1fr; gap:0; }
  .scan-panel { padding:18px; }
  .scan-heading { display:block; }
  .scan-form { flex-direction:column; }
  .scan-options { grid-template-columns:1fr; }
  button { width:100%; }
  .scan-meta { display:block; }
  .scan-meta p + p { margin-top:7px; }
  .panel { padding:18px; }
  .risk-summary { grid-template-columns:1fr; gap:9px; }
  h1 { letter-spacing:-1.2px; }
  td,th { padding:9px 6px; font-size:12px; }
}
@media(max-width:390px) {
  .grid { grid-template-columns:1fr 1fr; }
  .label { font-size:9px; }
  .brand { font-size:18px; }
}
</style>
</head>
<body>
<header>
  <div class="nav">
    <a class="brand" href="#top" aria-label="SecureScan home"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3 19 6v5c0 4.8-2.9 8.2-7 10-4.1-1.8-7-5.2-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/></svg></span><span>Secure<span>Scan</span></span></a>
    <nav class="nav-links" aria-label="Main navigation"><a href="#scan">New scan</a><a href="#results">Results</a><a href="#technical-details">Technical details</a></nav>
    <div class="status">● LOCAL DASHBOARD</div>
  </div>
</header>

<main id="top">
  <section class="hero">
    <div>
      <div class="eyebrow">Website security intelligence</div>
      <h1>See your website's security <span class="accent">clearly.</span></h1>
      <p class="hero-copy">Review your site's security posture, domain profile, hosting details and scan coverage. Quick mode checks one page; thorough mode follows a small same-origin set while respecting robots.txt. Forms are never submitted.</p>
    </div>
    <div class="hero-note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3 19 6v5c0 4.8-2.9 8.2-7 10-4.1-1.8-7-5.2-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/></svg>Passive checks · Authorized scans</div>
  </section>

  <section class="panel scan-panel" id="scan">
    <div class="scan-heading"><div><h2>Start a website scan</h2><p>Scan websites you own or are authorized to assess. Thorough scans are limited to ten same-origin pages.</p></div></div>
    <form id="scanForm" class="scan-form">
      <label class="sr-only" for="url">Website URL</label>
      <div class="input-wrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4M8.5 11h5M11 8.5v5"/></svg><input id="url" type="text" placeholder="Enter a domain or URL, e.g. example.com" required maxlength="2048" autocomplete="url" inputmode="url"></div>
      <button id="scanButton" type="submit"><svg class="button-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4M11 8v6m-3-3h6"/></svg>Run security scan</button>
      <button id="cancelScanButton" class="secondary" type="button" hidden>Stop scan</button>
    </form>
    <div class="scan-options">
      <div class="field"><label for="profile">Scan profile</label><select id="profile"><option value="quick">Quick · starting page only</option><option value="thorough">Thorough · up to 10 same-origin pages</option><option value="active">Safe active · CORS preflight</option></select><small>Thorough honors robots.txt. Safe active adds one HTTPS OPTIONS request; it sends no payloads and submits no forms.</small></div>
      <div class="field"><label for="authToken">Optional bearer token</label><input id="authToken" type="password" maxlength="4096" autocomplete="off" placeholder="Only for an authorized HTTPS site"><small>Sent only for this scan over HTTPS. It is not included in reports or history.</small></div>
    </div>
    <div id="progressWrap" class="progress-wrap" aria-live="polite"><div id="progressText" class="muted">Preparing scan…</div><div class="progress-track"><span id="progressBar"></span></div></div>
    <div class="scan-meta"><p id="message" role="status" aria-live="polite">Scans are limited to public websites and passive checks.</p><p class="permission"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>Public HTTP/HTTPS sites only</p></div>
  </section>

  <section class="grid">
    <div class="panel metric-card primary-metric"><div class="label">Observed risk score</div><div id="riskScore" class="metric">—</div></div>
    <div class="panel metric-card"><div class="label">Security findings</div><div id="findingCount" class="metric">—</div></div>
    <div class="panel metric-card"><div class="label">High / critical</div><div id="highCount" class="metric">—</div></div>
    <div class="panel metric-card"><div class="label">HTTPS enabled</div><div id="httpsStatus" class="metric">—</div></div>
    <div class="panel metric-card"><div class="label">TLS days remaining</div><div id="tlsDays" class="metric">—</div></div>
  </section>

  <div class="content-grid" id="results">
    <section class="panel">
      <div class="section-title"><h2>Security posture</h2><span class="section-kicker">Observed scan indicators</span></div>
      <div id="riskAssessment"><div class="empty-state">Run a scan to see the security posture and risk factors.</div></div>
    </section>
    <section class="panel">
      <div class="section-title"><h2>Scan overview</h2><span class="section-kicker">Target summary</span></div>
      <div id="overview"><div class="empty-state">Your scan summary will appear here.</div></div><div id="comparison" class="muted"></div>
    </section>
  </div>

  <section class="panel">
    <div class="section-title"><h2>Security findings</h2><span class="section-kicker">Issues and recommended actions</span></div>
    <div class="tool-row finding-controls"><div class="field"><label for="findingSearch">Search findings</label><input id="findingSearch" type="search" placeholder="Title or evidence"></div><div class="field"><label for="findingSeverity">Severity</label><select id="findingSeverity"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select></div><div class="field"><label for="findingStateFilter">Workflow state</label><select id="findingStateFilter"><option value="">All states</option><option value="open">Open</option><option value="fixed">Fixed</option><option value="accepted">Accepted</option><option value="false_positive">False positive</option></select></div></div>
    <div id="findings"><div class="empty-state">No scan results yet.</div></div>
  </section>

  <div class="two"><section class="panel"><div class="section-title"><h2>Page inventory</h2><span class="section-kicker">Checked and skipped URLs</span></div><div id="pageInventory"><p class="muted">Page details appear after a scan.</p></div></section><section class="panel"><div class="section-title"><h2>Coverage and sources</h2><span class="section-kicker">What was checked and where data came from</span></div><div id="coverage"><p class="muted">Coverage details appear after a scan.</p></div><div id="lookupNotes" class="muted" role="status"></div></section></div>

  <section class="panel" id="scan-history">
    <div class="section-title"><div><h2>Recent scan history</h2><span class="section-kicker">Stored locally; keeps up to 200 scans</span></div><div><button id="exportHistoryButton" class="secondary" type="button">Export history</button> <button id="clearHistoryButton" class="secondary" type="button" disabled>Clear history</button></div></div>
    <div class="tool-row"><div class="field"><label for="historyTarget">Filter by website</label><input id="historyTarget" type="search" placeholder="Domain"></div><div class="field"><label for="historySeverity">Finding severity</label><select id="historySeverity"><option value="">Any severity</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select></div><div class="field"><label for="historyState">Workflow state</label><select id="historyState"><option value="">Any state</option><option value="open">Open</option><option value="fixed">Fixed</option><option value="accepted">Accepted</option><option value="false_positive">False positive</option></select></div></div>
    <div id="history-list"><p class="muted">No saved scans yet.</p></div>
  </section>

  <div class="two">
    <section class="panel"><div class="section-title"><h2>Domain profile</h2><span class="section-kicker">Registration and country</span></div><div id="registration"><div class="empty-state">Domain details will appear after a scan.</div></div></section>
    <section class="panel">
      <div class="section-title"><h2>Hosting and location</h2><span class="section-kicker">Public IP intelligence</span></div><div id="hosting"><div class="empty-state">Hosting details will appear after a scan.</div></div>
      <p class="section-kicker">IP location is approximate. CDNs, proxies and shared hosting may hide the origin server.</p>
    </section>
  </div>

  <div class="two" id="technical-details">
    <section class="panel"><div class="section-title"><h2>TLS certificate</h2><span class="section-kicker">Encrypted connection</span></div><div id="tls"><div class="empty-state">TLS certificate details will appear after a scan.</div></div></section>
    <section class="panel"><div class="section-title"><h2>DNS records</h2><span class="section-kicker">Domain name system</span></div><div id="dns" class="dns-records"><div class="empty-state">DNS details will appear after a scan.</div></div></section>
  </div>
  <section class="panel"><div class="section-title"><h2>Email domain security</h2><span class="section-kicker">SPF, DMARC and common DKIM selectors</span></div><div id="email-security"><div class="empty-state">Email DNS checks will appear after a scan.</div></div></section>

  <details class="panel report-details">
    <summary><h2>Technical report</h2><span class="section-kicker">Full JSON output and export</span></summary>
    <p>Download or inspect the full scan response for additional technical context.</p>
    <div class="section-title"><button id="downloadButton" class="secondary" type="button" disabled><svg class="button-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3v12m0 0 4-4m-4 4-4-4M5 17v3h14v-3"/></svg>Export JSON report</button><button id="printButton" class="secondary print-button" type="button" disabled>Print / Save as PDF</button></div>
    <pre id="jsonReport">Run a scan to generate a report.</pre>
  </details>
</main>

<footer>SecureScan · Educational security assessment tool</footer>

<script>
const form = document.getElementById("scanForm");
const urlInput = document.getElementById("url");
const button = document.getElementById("scanButton");
const cancelScanButton = document.getElementById("cancelScanButton");
const message = document.getElementById("message");
const downloadButton = document.getElementById("downloadButton");
const printButton = document.getElementById("printButton");
const clearHistoryButton = document.getElementById("clearHistoryButton");
const authTokenInput = document.getElementById("authToken");
const progressWrap = document.getElementById("progressWrap");
let lastReport = null;
let progressTimer = null;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[character]);
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return '<span class="muted">Unavailable</span>';
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return '<span class="muted">No records found</span>';
    }

    return '<ul>' + value.map(item =>
      '<li>' + formatValue(item) + '</li>'
    ).join("") + '</ul>';
  }

  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      return '<span class="muted">No details available</span>';
    }

    return '<ul>' + entries.map(([key, val]) =>
      '<li><strong>' + escapeHtml(key.replaceAll("_", " ")) +
      ':</strong> ' + formatValue(val) + '</li>'
    ).join("") + '</ul>';
  }

  return escapeHtml(value);
}

function table(data) {
  const rows = Object.entries(data || {});
  if (!rows.length) {
    return '<p class="muted">Information unavailable.</p>';
  }

  return '<table><tbody>' + rows.map(([key, value]) =>
    '<tr><td>' + escapeHtml(key.replaceAll("_", " ")) +
    '</td><td>' + formatValue(value) + '</td></tr>'
  ).join("") + '</tbody></table>';
}

function countryName(code) {
  if (!code) return null;
  try {
    return new Intl.DisplayNames(["en"], {type:"region"}).of(code);
  } catch (_) {
    return null;
  }
}

function renderRiskAssessment(risk) {
  if (!risk || typeof risk.score_percent !== "number") {
    return '<p class="muted">Risk score unavailable.</p>';
  }

  const score = Math.max(0, Math.min(100, risk.score_percent));
  const level = escapeHtml(risk.level || "Unknown");
  const checks = Array.isArray(risk.checks) ? risk.checks : [];
  const checkCards = checks.length ? checks.map(check => {
    const status = String(check.status || "info").toLowerCase();
    return '<div class="finding"><div class="severity ' +
      escapeHtml(status) + '">' + escapeHtml(status) +
      '</div><h3>' + escapeHtml(check.check || "Check") +
      '</h3><div>' + escapeHtml(check.evidence || "") +
      '</div><div class="muted">Risk points: ' +
      escapeHtml(check.points ?? 0) + ' / ' +
      escapeHtml(check.maximum_points ?? 0) + '</div></div>';
  }).join("") : '<p class="muted">No checks were available.</p>';

  return '<div class="risk-summary"><div><div class="risk-number">' +
    score + '<small> / 100</small></div><span class="severity ' +
    level.toLowerCase() + '">' + level + ' observed risk</span></div>' +
    '<div><div class="label">Weighted risk indicators</div>' +
    '<progress class="risk-meter" data-level="' + level +
    '" max="100" value="' + score + '" aria-label="Observed risk score"></progress>' +
    '<p>' + escapeHtml(risk.checks_with_risk ?? 0) + ' of ' +
    escapeHtml(risk.checks_evaluated ?? 0) +
    ' evaluated checks showed a risk indicator.</p></div></div>' +
    '<div class="risk-checks">' + checkCards + '</div>' +
    '<p class="risk-limit">' + escapeHtml(risk.limitation || "") + '</p>';
}

function renderFindings() {
  const findings = Array.isArray(lastReport?.findings) ? lastReport.findings : [];
  const query = document.getElementById("findingSearch").value.trim().toLowerCase();
  const severityFilter = document.getElementById("findingSeverity").value.toLowerCase();
  const stateFilter = document.getElementById("findingStateFilter").value;
  const visible = findings.filter(item => {
    const text = [item.title, item.description, item.evidence].join(" ").toLowerCase();
    return (!query || text.includes(query)) && (!severityFilter || String(item.severity).toLowerCase() === severityFilter) && (!stateFilter || (item.workflow_state || "open") === stateFilter);
  });
  document.getElementById("findings").innerHTML = visible.length ? visible.map(item => {
    const severity = String(item.severity || "info").toLowerCase(), state = item.workflow_state || "open";
    return '<article class="finding" data-finding-id="' + escapeHtml(item.finding_id) + '"><div class="severity ' + escapeHtml(severity) + '">' + escapeHtml(severity) + '</div><h3>' + escapeHtml(item.title || "Finding") + '</h3><p>' + escapeHtml(item.description || "") + '</p>' + (item.recommendation ? '<p><strong>Recommendation:</strong> ' + escapeHtml(item.recommendation) + '</p>' : '') + '<p class="muted"><strong>Confidence:</strong> ' + escapeHtml(item.confidence || "Medium") + (item.evidence ? ' · <strong>Evidence:</strong> ' + escapeHtml(item.evidence) : '') + '</p><div class="finding-state"><label>State <select class="state-select"><option value="open" ' + (state === "open" ? "selected" : "") + '>Open</option><option value="fixed" ' + (state === "fixed" ? "selected" : "") + '>Fixed</option><option value="accepted" ' + (state === "accepted" ? "selected" : "") + '>Accepted</option><option value="false_positive" ' + (state === "false_positive" ? "selected" : "") + '>False positive</option></select></label><input class="state-reason" maxlength="500" placeholder="Reason (required for false positive)" value="' + escapeHtml(item.state_reason || "") + '"><button class="secondary save-state" type="button">Save state</button></div></article>';
  }).join("") : '<p class="muted">No findings match these filters.</p>';
}

function render(report) {
  lastReport = report;
  downloadButton.disabled = false;
  printButton.disabled = false;

  const counts = report.severity_counts || {};
  document.getElementById("findingCount").textContent =
    report.finding_count ?? 0;

  document.getElementById("highCount").textContent =
    Number(counts.High || 0) + Number(counts.Critical || 0);

  document.getElementById("httpsStatus").textContent =
    report.https ? "Yes" : "No";

  const tls = report.tls_intelligence || {};
  const days = tls.days_remaining;
  const risk = report.risk_assessment || {};

  document.getElementById("riskScore").textContent =
    typeof risk.score_percent === "number" ? risk.score_percent + "%" : "N/A";
  document.getElementById("riskAssessment").innerHTML =
    renderRiskAssessment(risk);

  document.getElementById("tlsDays").textContent =
    days === null || days === undefined ? "—" : String(days);

  document.getElementById("overview").innerHTML = table({
    target: report.target,
    final_url: report.final_url,
    scan_profile: report.scan_profile,
    scan_scope: report.scope,
    scan_status: report.status,
    http_status_code: report.status_code,
    scan_time: report.scan_time
  });
  const comparison = report.comparison || {};
  document.getElementById("comparison").innerHTML = comparison.available
    ? '<p><strong>Since previous scan:</strong> risk score ' +
      (comparison.risk_score_change > 0 ? '+' : '') + escapeHtml(comparison.risk_score_change) +
      ' points; ' + escapeHtml((comparison.new_findings || []).length) +
      ' new and ' + escapeHtml((comparison.resolved_findings || []).length) + ' resolved findings.</p>'
    : '<p>' + escapeHtml(comparison.message || "No comparison available.") + '</p>';

  const domain = report.domain_intelligence || {};

  let registrationNote = "";
  if (domain.registration_error) {
    registrationNote = domain.registration_error;
  } else if (domain.registration_available === false) {
    registrationNote =
      "Registration data could not be confirmed. This does not necessarily mean the domain is unregistered.";
  }

  document.getElementById("registration").innerHTML =
    table({
      domain: domain.domain,
      domain_suffix: domain.top_level_domain,
      country_code_domain: domain.country_code_domain,
      suffix_country_association: countryName(domain.country_code_domain),
      suffix_location_note: "A country-code suffix does not establish the registrant's or server's location.",
      registration_lookup: domain.registration_available
        ? "Registration data retrieved"
        : "Registration data unavailable",
      registration_source: domain.registration_source,
      registrant_country: report.registration_country,
      registrant_name: domain.registrant,
      registrar: domain.registrar,
      registrar_country: domain.registrar_country,
      website_first_archived_date: domain.website_first_archived_date,
      website_creation_date_note: domain.website_creation_date_note,
      registration_date: domain.registration_date,
      expiration_date: domain.expiration_date,
      last_updated: domain.last_updated,
      domain_status: domain.status,
      nameservers: domain.nameservers,
      lookup_note: registrationNote || null
    }) + (domain.lookup_url
      ? '<p><a href="' + escapeHtml(domain.lookup_url) +
        '" target="_blank" rel="noopener noreferrer">Open official LK Domain Registry lookup ↗</a></p>'
      : '');

  const geo = report.ip_geolocation || {};

  document.getElementById("hosting").innerHTML = table({
    ip_address: geo.ip,
    all_public_ips: domain.ip_addresses,
    country: geo.country,
    country_code: geo.country_code,
    region: geo.region,
    city: geo.city,
    isp: geo.isp,
    organization: geo.organization,
    ASN: geo.asn,
    location_type: geo.location_type,
    location_lookup: geo.error,
    location_source: geo.source
  });

  document.getElementById("tls").innerHTML = table({
    certificate_valid: tls.certificate_valid,
    subject: tls.subject,
    issuer: tls.issuer,
    valid_from: tls.valid_from,
    valid_until: tls.valid_until,
    days_remaining: tls.days_remaining,
    TLS_version: tls.tls_version,
    cipher: tls.cipher,
    certificate_version: tls.version,
    serial_number: tls.serial_number,
    subject_alternative_names: tls.subject_alt_names,
    warning: tls.warning,
    error: tls.error
  });

  document.getElementById("dns").innerHTML = table(
    domain.dns || {}
  );
  document.getElementById("email-security").innerHTML = table(
    domain.email_security || {}
  );

  const findings = Array.isArray(report.findings)
    ? report.findings : [];

  document.getElementById("findings").innerHTML = findings.length
    ? findings.map(item => {
        const severity = String(item.severity || "info").toLowerCase();
        return '<div class="finding" data-finding-id="' + escapeHtml(item.finding_id) + '"><div class="severity ' +
          escapeHtml(severity) + '">' + escapeHtml(severity) +
          '</div><h3>' + escapeHtml(item.title || "Finding") +
          '</h3><div>' + escapeHtml(item.description || "") +
          '</div>' + (item.recommendation
            ? '<p><strong>Recommendation:</strong> ' +
              escapeHtml(item.recommendation) + '</p>' : '') +
          '<p class="muted"><strong>Confidence:</strong> ' + escapeHtml(item.confidence || "Medium") +
          (item.evidence ? ' Â· <strong>Evidence:</strong> ' + escapeHtml(item.evidence) : '') + '</p>' +
          '</p><div class="finding-state"><label>State <select class="state-select"><option value="open" ' + ((item.workflow_state || "open") === "open" ? "selected" : "") + '>Open</option><option value="fixed" ' + (item.workflow_state === "fixed" ? "selected" : "") + '>Fixed</option><option value="accepted" ' + (item.workflow_state === "accepted" ? "selected" : "") + '>Accepted</option><option value="false_positive" ' + (item.workflow_state === "false_positive" ? "selected" : "") + '>False positive</option></select></label><input class="state-reason" maxlength="500" placeholder="Reason (required for false positive)" value="' + escapeHtml(item.state_reason || "") + '"><input class="state-expiry" type="date" aria-label="Optional state expiry" value="' + escapeHtml((item.state_expires_at || "").slice(0,10)) + '"><button class="secondary save-state" type="button">Save state</button></div>' +
          '</div>';
      }).join("")
    : '<p class="muted">No findings were returned by the scanner.</p>';

  document.getElementById("jsonReport").textContent =
    JSON.stringify(report, null, 2);
  const pages = report.pages || [], skipped = report.pages_skipped || [];
  document.getElementById("pageInventory").innerHTML = pages.length || skipped.length ? '<table><thead><tr><th>Page</th><th>State</th><th>Observed</th></tr></thead><tbody>' + pages.map(page => { const facts = [page.status_code ? 'HTTP ' + page.status_code : '', page.html_inspected ? 'HTML inspected' : 'HTML unavailable', Number.isInteger(page.headers_checked) ? page.headers_checked + ' headers' : '', Number.isInteger(page.cookies_checked) ? page.cookies_checked + ' cookies' : '', Array.isArray(page.forms_found) ? page.forms_found.length + ' forms' : '', page.resource_count ? page.resource_count + ' resources' : ''].filter(Boolean).join(' · '); const hints = (page.api_spec_hints || []).map(url => '<br>API spec hint: ' + escapeHtml(url)).join(''); const forms = (page.forms_found || []).map(form => '<br>Form ' + escapeHtml(form.method) + ': ' + escapeHtml(form.action || '(current page)') + (form.contains_password ? ' (password field)' : '')).join(''); const api = page.api_spec ? '<br>API: ' + escapeHtml(page.api_spec.title) + ' (' + escapeHtml(page.api_spec.endpoint_count) + ' endpoints)' + (page.api_spec.paths || []).map(item => '<br>' + escapeHtml((item.methods || []).join(', ')) + ' ' + escapeHtml(item.path)).join('') : ''; return '<tr><td>' + escapeHtml(page.url) + '</td><td>' + escapeHtml(page.state) + '</td><td>' + escapeHtml(page.error || facts) + forms + hints + api + '</td></tr>'; }).join('') + skipped.map(page => '<tr><td>' + escapeHtml(page.url) + '</td><td>Skipped</td><td>' + escapeHtml(page.reason) + '</td></tr>').join('') + '</tbody></table>' : '<p class="muted">No page inventory returned.</p>';
  const coverage = report.coverage || [];
  document.getElementById("coverage").innerHTML = coverage.length ? '<table><tbody>' + coverage.map(item => '<tr><td>' + escapeHtml(item.check) + '</td><td>' + escapeHtml(item.status) + '</td><td>' + escapeHtml(item.source) + '<br>' + escapeHtml(item.checked_at || 'Time unavailable') + '</td></tr>').join('') + '</tbody></table>' : '<p class="muted">Coverage metadata unavailable.</p>';
  const notes = report.intelligence_errors || [];
  document.getElementById("lookupNotes").innerHTML = notes.length ? '<p><strong>Lookup notes</strong></p><ul>' + notes.map(note => '<li>' + escapeHtml(note) + '</li>').join('') + '</ul><p>Some registrant details may be redacted by the registry. IP locations are estimates; a CDN or proxy may mask the origin server.</p>' : '<p>Unavailable values usually mean the source did not publish the data or the lookup service did not return it. This is not proof that the record or issue is absent.</p>';
}

form.addEventListener("submit", async event => {
  event.preventDefault();

  let url = urlInput.value.trim();
  if (!url) return;

  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  button.disabled = true;
  button.textContent = "Scanning...";
  cancelScanButton.hidden = false;
  progressWrap.classList.add("active");
  document.getElementById("progressBar").style.width = "8%";
  message.textContent =
    "Running security, domain and TLS checks. This may take several seconds.";
  const payload = {url, authorized:true, profile:document.getElementById("profile").value};
  if (authTokenInput.value) payload.auth_token = authTokenInput.value;
  authTokenInput.value = "";
  clearInterval(progressTimer);
  progressTimer = setInterval(async () => { try { const status = await (await fetch("/api/scan/status", {cache:"no-store"})).json(); document.getElementById("progressText").textContent = status.message || "Scanning…"; const n = status.total ? Math.min(95, Math.round(status.completed / status.total * 100)) : 12; document.getElementById("progressBar").style.width = Math.max(8, n) + "%"; } catch (_) {} }, 900);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "The scan could not be completed.");
    }

    render(data);
    await loadHistory();
    message.textContent = "Scan completed. Review your results below.";
    document.getElementById("results").scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  } catch (error) {
    message.textContent = error.message || "Unexpected error.";
  } finally {
    clearInterval(progressTimer);
    progressWrap.classList.remove("active");
    cancelScanButton.hidden = true;
    button.disabled = false;
    button.textContent = "Run security scan";
  }
});

cancelScanButton.addEventListener("click", async () => {
  cancelScanButton.disabled = true;
  message.textContent = "Requesting scan cancellation; the current network request may need to time out first.";
  try { await fetch("/api/scan/cancel", {method:"POST"}); }
  catch (_) { message.textContent = "Could not contact the scanner to stop the scan."; }
  finally { cancelScanButton.disabled = false; }
});

async function loadHistory() {
  const container = document.getElementById("history-list");
  try {
    const params = new URLSearchParams();
    const target = document.getElementById("historyTarget").value.trim();
    const severity = document.getElementById("historySeverity").value;
    const state = document.getElementById("historyState").value;
    if (target) params.set("target", target);
    if (severity) params.set("severity", severity);
    if (state) params.set("state", state);
    const response = await fetch("/api/history?" + params.toString());
    const data = await response.json();
    const scans = Array.isArray(data.scans) ? data.scans : [];
    clearHistoryButton.disabled = scans.length === 0;
    container.innerHTML = scans.length
      ? '<table><thead><tr><th>Website</th><th>Scanned</th><th>Risk</th><th>Findings</th><th>Actions</th></tr></thead><tbody>' +
        scans.map(scan => '<tr><td>' + escapeHtml(scan.target) + '</td><td>' +
          escapeHtml(scan.scan_time) + '</td><td>' + escapeHtml(scan.risk_score ?? "N/A") +
          '% (' + escapeHtml(scan.risk_level || "Unknown") + ')</td><td>' +
          escapeHtml(scan.finding_count) + '</td><td><button class="secondary history-view" data-id="' + escapeHtml(scan.id) + '" type="button">View</button> <button class="secondary history-delete" data-id="' + escapeHtml(scan.id) + '" type="button">Delete</button></td></tr>').join("") + '</tbody></table>'
      : '<p class="muted">No saved scans yet.</p>';
  } catch (_) {
    container.innerHTML = '<p class="muted">Scan history is temporarily unavailable.</p>';
  }
}

clearHistoryButton.addEventListener("click", async () => {
  if (!confirm("Delete all locally saved scan history? This cannot be undone.")) return;
  clearHistoryButton.disabled = true;
  try {
    const response = await fetch("/api/history", {method:"DELETE"});
    if (!response.ok) throw new Error("History could not be cleared.");
    await loadHistory();
  } catch (error) {
    message.textContent = error.message || "History could not be cleared.";
    clearHistoryButton.disabled = false;
  }
});

loadHistory();

function filterFindings() {
  const query = document.getElementById("findingSearch").value.toLowerCase();
  const severity = document.getElementById("findingSeverity").value.toLowerCase();
  const state = document.getElementById("findingStateFilter").value;
  document.querySelectorAll("#findings [data-finding-id]").forEach(card => {
    const item = lastReport?.findings?.find(f => f.finding_id === card.dataset.findingId);
    const match = item && (!query || [item.title,item.description,item.evidence].join(" ").toLowerCase().includes(query)) && (!severity || item.severity.toLowerCase() === severity) && (!state || (item.workflow_state || "open") === state);
    card.hidden = !match;
  });
}
for (const id of ["findingSearch", "findingSeverity", "findingStateFilter"]) {
  document.getElementById(id).addEventListener("input", filterFindings);
  document.getElementById(id).addEventListener("change", filterFindings);
}
document.getElementById("findings").addEventListener("click", async event => {
  if (!event.target.matches(".save-state") || !lastReport) return;
  const card = event.target.closest("[data-finding-id]"), item = lastReport.findings.find(f => f.finding_id === card.dataset.findingId);
  const state = card.querySelector(".state-select").value, reason = card.querySelector(".state-reason").value.trim();
  if (state === "false_positive" && !reason) { message.textContent = "A reason is required for false positives."; return; }
  const saveButton = event.target; saveButton.disabled = true;
  try {
    const expiryDate = card.querySelector(".state-expiry").value;
    const response = await fetch("/api/findings/state", {method:"PUT", headers:{"Content-Type":"application/json"}, body:JSON.stringify({target:lastReport.target, finding_id:item.finding_id, state, reason, expires_at:expiryDate ? new Date(expiryDate + "T23:59:59Z").toISOString() : null})});
    const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Could not save finding state.");
    item.workflow_state = state; item.state_reason = reason || null; item.state_expires_at = expiryDate || null;
    document.getElementById("jsonReport").textContent = JSON.stringify(lastReport, null, 2);
    card.querySelector(".finding-state").insertAdjacentHTML("beforeend", '<span class="muted">Saved</span>');
    message.textContent = "Finding state saved for this host."; filterFindings(); await loadHistory();
  } catch (error) { message.textContent = error.message; }
  finally { saveButton.disabled = false; }
});

for (const id of ["historyTarget", "historySeverity", "historyState"]) {
  document.getElementById(id).addEventListener(id === "historyTarget" ? "input" : "change", () => { clearTimeout(window.historyFilterTimer); window.historyFilterTimer = setTimeout(loadHistory, 250); });
}
document.getElementById("history-list").addEventListener("click", async event => {
  const id = event.target.dataset.id;
  if (!id) return;
  try {
    if (event.target.matches(".history-delete")) {
      const response = await fetch("/api/history/" + encodeURIComponent(id), {method:"DELETE"});
      if (!response.ok) throw new Error("Saved scan could not be deleted.");
      await loadHistory();
    } else if (event.target.matches(".history-view")) {
      const response = await fetch("/api/history/" + encodeURIComponent(id));
      const report = await response.json();
      if (!response.ok) throw new Error(report.detail || "Saved scan could not be opened.");
      render(report);
      document.getElementById("results").scrollIntoView({behavior:"smooth", block:"start"});
    }
  } catch (error) { message.textContent = error.message; }
});
document.getElementById("exportHistoryButton").addEventListener("click", async () => {
  const response = await fetch("/api/history/export"); const data = await response.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
  const url = URL.createObjectURL(blob); const link = document.createElement("a");
  link.href = url; link.download = "securescan_history.json"; link.click(); URL.revokeObjectURL(url);
});

downloadButton.addEventListener("click", () => {
  if (!lastReport) return;

  const blob = new Blob(
    [JSON.stringify(lastReport, null, 2)],
    {type:"application/json"}
  );

  const downloadUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = "securescan_report.json";
  link.click();
  URL.revokeObjectURL(downloadUrl);
});

printButton.addEventListener("click", () => {
  if (lastReport) window.print();
});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
