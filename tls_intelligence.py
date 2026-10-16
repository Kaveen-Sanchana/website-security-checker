import json
import socket
import ssl
import sys
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse


USER_AGENT = "SecureScan-TLSIntelligence/1.0"


def normalize_hostname(target):
    """Extract and validate a public hostname from a URL."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Please provide a domain name or URL.")

    target = target.strip()

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme.lower() != "https":
        raise ValueError("Please provide an HTTPS URL.")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("The URL does not contain a valid hostname.")

    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("The hostname format is invalid.")

    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal", ".test", ".invalid")
    ):
        raise ValueError("Local or reserved hostnames are not supported.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        if not address.is_global:
            raise ValueError("Private or non-public IP addresses are not supported.")

        raise ValueError("Please provide a domain name, not a direct IP address.")

    labels = hostname.split(".")

    if len(labels) < 2:
        raise ValueError("Please provide a complete domain name.")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise ValueError("The hostname format is invalid.")

    return hostname


def inspect_tls_certificate(target, resolved_ips=None):
    """Inspect a public HTTPS server's TLS certificate."""

    hostname = normalize_hostname(target)

    result = {
        "target": target,
        "hostname": hostname,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "tls_connection_successful": False,
        "certificate_valid": False,
        "certificate_subject": None,
        "certificate_issuer": None,
        "valid_from_utc": None,
        "valid_until_utc": None,
        "days_until_expiration": None,
        "subject_alternative_names": [],
        "certificate_version": None,
        "serial_number": None,
        "error": None,
        "limitations": [
            "This checks the certificate presented by the server on port 443.",
            "A valid certificate does not prove that a website is free from vulnerabilities.",
            "Certificate details can vary between servers, regions, and CDN endpoints.",
        ],
    }

    try:
        # Reuse the address validated by the HTTP scan where possible. For
        # standalone calls, resolve and filter the public addresses here.
        public_addresses = []
        for value in resolved_ips or []:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global and str(address) not in public_addresses:
                public_addresses.append(str(address))
        if not public_addresses:
            addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            public_addresses = sorted({
                item[4][0]
                for item in addresses
                if ipaddress.ip_address(item[4][0]).is_global
            }, key=lambda value: (ipaddress.ip_address(value).version, value))

        if not public_addresses:
            raise ValueError(
                "The hostname did not resolve to a public IP address."
            )

        # The default context verifies the certificate chain and hostname.
        context = ssl.create_default_context()

        # Connect to the exact public address validated above while keeping
        # the domain name for SNI and certificate hostname verification.
        with socket.create_connection(
            (public_addresses[0], 443),
            timeout=8,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                result["tls_connection_successful"] = True
                result["certificate_valid"] = True
                result["tls_version"] = tls_socket.version()
                result["cipher"] = tls_socket.cipher()[0]

                subject = certificate.get("subject", ())
                issuer = certificate.get("issuer", ())

                def flatten_name(name):
                    values = []
                    for group in name:
                        for key, value in group:
                            values.append(f"{key}={value}")
                    return ", ".join(values) if values else None

                result["certificate_subject"] = flatten_name(subject)
                result["certificate_issuer"] = flatten_name(issuer)

                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                def parse_certificate_date(value):
                    if not value:
                        return None

                    parsed_date = datetime.strptime(
                        value,
                        "%b %d %H:%M:%S %Y %Z",
                    )

                    return parsed_date.replace(tzinfo=timezone.utc)

                valid_from = parse_certificate_date(not_before)
                valid_until = parse_certificate_date(not_after)

                result["valid_from_utc"] = (
                    valid_from.isoformat() if valid_from else None
                )
                result["valid_until_utc"] = (
                    valid_until.isoformat() if valid_until else None
                )

                if valid_until:
                    remaining = valid_until - datetime.now(timezone.utc)
                    result["days_until_expiration"] = remaining.days

                result["subject_alternative_names"] = [
                    value
                    for name_type, value in certificate.get(
                        "subjectAltName", ()
                    )
                    if name_type == "DNS"
                ]

                result["certificate_version"] = certificate.get("version")
                result["serial_number"] = certificate.get("serialNumber")

                if valid_until:
                    if result["days_until_expiration"] < 0:
                        result["warning"] = "The certificate has expired."
                    elif result["days_until_expiration"] <= 14:
                        result["warning"] = (
                            "The certificate expires within 14 days."
                        )
                    elif result["days_until_expiration"] <= 30:
                        result["warning"] = (
                            "The certificate expires within 30 days."
                        )
                    else:
                        result["warning"] = None

    except ValueError as exc:
        result["error"] = str(exc)

    except socket.gaierror:
        result["error"] = "The hostname could not be resolved."

    except socket.timeout:
        result["error"] = "The TLS connection timed out."

    except ssl.SSLCertVerificationError as exc:
        result["error"] = (
            "Certificate verification failed: " + str(exc)
        )

    except ssl.SSLError as exc:
        result["error"] = "TLS error: " + str(exc)

    except OSError as exc:
        result["error"] = (
            "Could not connect to the HTTPS server: " + str(exc)
        )

    except Exception as exc:
        result["error"] = (
            "Unexpected error: " + type(exc).__name__
        )

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python tls_intelligence.py https://example.com"
        )
        sys.exit(1)

    report = inspect_tls_certificate(sys.argv[1])
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if report["error"]:
        sys.exit(1)
