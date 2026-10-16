
import json
import socket
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

import scanner


class ScannerTests(unittest.TestCase):

    def make_response(
        self,
        status_code=200,
        headers=None,
        url="https://example.com",
    ):
        class FakeResponse:
            def __init__(self):
                self.status_code = status_code
                self.url = url
                self.headers = headers or {}
                self.closed = False

            def close(self):
                self.closed = True

        return FakeResponse()

    def run_scan(self, response):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_open = open

            def temporary_open(file, mode="r", *args, **kwargs):
                destination = Path(temp_dir) / Path(file).name
                return original_open(destination, mode, *args, **kwargs)

            with patch(
                "scanner.socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("93.184.216.34", 443))
                ],
            ), patch(
                "scanner._safe_get",
                return_value=response,
            ), patch(
                "scanner.open",
                create=True,
                side_effect=temporary_open,
            ), patch("builtins.print"):
                scanner.scan_website("https://example.com")

            text_path = Path(temp_dir) / "scan_report.txt"
            json_path = Path(temp_dir) / "scan_report.json"

            self.assertTrue(text_path.exists())
            self.assertTrue(json_path.exists())

            text_report = text_path.read_text(encoding="utf-8")
            json_report = json.loads(
                json_path.read_text(encoding="utf-8")
            )

            return text_report, json_report

    def test_reports_created_and_headers_found(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }

        text_report, report = self.run_scan(
            self.make_response(headers=headers)
        )

        self.assertIn("SIMPLE WEB VULNERABILITY SCANNER", text_report)
        self.assertEqual(report["http_status"], 200)
        self.assertEqual(report["summary"]["headers_found"], 6)
        self.assertEqual(report["summary"]["headers_missing"], 0)

    def test_redirect_is_reported(self):
        response = self.make_response(
            status_code=301,
            headers={"Location": "https://www.example.com"},
        )

        _, report = self.run_scan(response)
        titles = [item["title"] for item in report["findings"]]

        self.assertIn("Redirect detected", titles)

    def test_redirect_to_localhost_is_rejected_before_second_request(self):
        response = self.make_response(
            status_code=302,
            headers={"Location": "http://127.0.0.1/admin"},
        )

        with patch(
            "scanner.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("93.184.216.34", 443))
            ],
        ), patch(
            "scanner._safe_get",
            return_value=response,
        ) as mock_get, patch("builtins.print"):
            with self.assertRaisesRegex(ValueError, "non-public IP"):
                scanner.scan_website("https://example.com")

        self.assertEqual(mock_get.call_count, 1)

    def test_http_error_is_reported(self):
        _, report = self.run_scan(
            self.make_response(status_code=404)
        )
        titles = [item["title"] for item in report["findings"]]

        self.assertIn("HTTP error response", titles)

    def test_missing_security_headers_are_reported(self):
        _, report = self.run_scan(
            self.make_response(headers={})
        )
        titles = [item["title"] for item in report["findings"]]

        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Missing X-Frame-Options", titles)
        self.assertEqual(report["summary"]["headers_missing"], 6)

    def test_http_skips_hsts_check(self):
        response = self.make_response(
            status_code=200,
            url="http://example.com",
        )

        _, report = self.run_scan(response)

        self.assertEqual(report["summary"]["headers_skipped"], 1)
        self.assertEqual(report["summary"]["headers_missing"], 5)

    def test_valid_public_hostname_is_accepted(self):
        with patch(
            "scanner.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("93.184.216.34", 443))
            ],
        ):
            result = scanner.validate_url("https://example.com")

        self.assertEqual(result, "https://example.com")

    def test_hostname_is_added_to_url_without_scheme(self):
        with patch(
            "scanner.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("93.184.216.34", 443))
            ],
        ):
            result = scanner.validate_url("example.com")

        self.assertEqual(result, "https://example.com")

    def test_empty_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "enter a website URL"):
            scanner.validate_url("")

    def test_url_with_spaces_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unescaped spaces"):
            scanner.validate_url("not a website")

    def test_localhost_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Localhost"):
            scanner.validate_url("http://localhost")

    def test_private_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-public IP"):
            scanner.validate_url("http://127.0.0.1")

    def test_unresolvable_hostname_is_rejected(self):
        with patch(
            "scanner.socket.getaddrinfo",
            side_effect=socket.gaierror,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "could not be resolved",
            ):
                scanner.validate_url(
                    "https://secure-scan-test-domain-12345.com"
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
