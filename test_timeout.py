
import io
from contextlib import redirect_stdout
from unittest.mock import patch

import requests
import scanner


def test_timeout_message():
    output = io.StringIO()

    with patch(
        "builtins.input",
        side_effect=["https://example.com", "yes"],
    ), patch(
        "scanner._safe_get",
        side_effect=requests.exceptions.Timeout,
    ), patch(
        "scanner.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443))
        ],
    ), redirect_stdout(output):
        scanner.main()

    result = output.getvalue()

    expected_message = (
        "Error: The website took too long to respond."
    )

    assert expected_message in result


def test_cli_cancels_without_authorization():
    output = io.StringIO()

    with patch(
        "builtins.input",
        side_effect=["https://example.com", "no"],
    ), patch("scanner.scan_website") as scan, redirect_stdout(output):
        scanner.main()

    assert "Scan cancelled" in output.getvalue()
    scan.assert_not_called()


if __name__ == "__main__":
    test_timeout_message()
