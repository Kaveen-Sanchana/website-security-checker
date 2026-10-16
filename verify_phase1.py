
"""Live HTTP, HTTPS, and IP-pinning verification for SecureScan."""

import ipaddress
import sys
from urllib.parse import urlparse

import scanner


TARGETS = [
    "https://example.com/",
    "http://example.com/",
]


def verify_target(url):
    print("\n" + "=" * 65)
    print("Testing:", url)
    print("=" * 65)

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    validated_ips = scanner._resolve_public_addresses(hostname, port)
    print("Validated public IPs:", ", ".join(validated_ips))

    response = None

    try:
        response = scanner._safe_get(url)

        connection = getattr(response.raw, "_connection", None)
        sock = getattr(connection, "sock", None)

        if sock is None:
            raise RuntimeError(
                "The active socket is unavailable for inspection. "
                "The IP-pinning result is inconclusive."
            )

        peer_ip = str(ipaddress.ip_address(sock.getpeername()[0]))

        print("Actual TCP peer IP:", peer_ip)
        print("HTTP status:", response.status_code)

        if peer_ip not in validated_ips:
            raise AssertionError(
                f"Connected to {peer_ip}, which was not in the "
                f"validated address list: {validated_ips}"
            )

        if parsed.scheme == "https":
            cipher = sock.cipher()
            if not cipher:
                raise AssertionError("No active TLS cipher was detected.")

            print("TLS cipher:", cipher[0])
            print("Certificate verification: enabled")
            print("HTTPS connection: successful")
        else:
            print("HTTP connection: successful")

        print("RESULT: PASS")
        return True

    finally:
        if response is not None:
            response.close()


def main():
    print("SecureScan - Phase 1 Live Connection Verification")
    print("This test needs an active internet connection.")

    passed = 0
    failed = 0

    for url in TARGETS:
        try:
            if verify_target(url):
                passed += 1
        except Exception as error:
            failed += 1
            print("\nRESULT: FAIL")
            print(f"Reason: {type(error).__name__}: {error}")

    print("\n" + "=" * 65)
    print("VERIFICATION SUMMARY")
    print("=" * 65)
    print("Passed:", passed)
    print("Failed:", failed)

    if failed:
        print(
            "\nAt least one live check failed or was inconclusive. "
            "Do not treat IP pinning as verified yet."
        )
        sys.exit(1)

    print("\nBoth live connection checks passed.")


if __name__ == "__main__":
    main()
