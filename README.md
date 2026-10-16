# SecureScan

SecureScan is a local website configuration and security review tool. It combines passive HTTP/HTML checks with TLS, DNS, registration, and approximate public-IP information, then records scan history and finding workflow states locally.

## Run locally

Use Python 3.11 or newer. Install the application dependencies:

```powershell
python -m pip install fastapi uvicorn requests dnspython urllib3
```

Start the dashboard on the local machine:

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Starting a scan from the dashboard sends an authorization acknowledgment with the scan request; the command-line scanner asks for confirmation. SecureScan cannot independently verify ownership or permission. The default server binding is loopback so the dashboard is not exposed to the network by default.

## Scan profiles and findings

- Public DNS and registration metadata, TLS certificate information, and approximate IP geolocation.
- Security response headers and cookie attributes. Cookie values are not saved in scan reports.
- **Quick** checks the final page. **Thorough** reads robots.txt, checks same-origin sitemap references, then follows at most 10 same-origin pages and skips disallowed pages. The page inventory shows checked and skipped pages.
- The thorough page inventory includes response header and cookie checks, form field names/types (never values), linked API specification hints, and parsed OpenAPI paths when an in-scope JSON document is linked.
- **Safe active** adds one HTTPS OPTIONS preflight using a reserved synthetic origin to check credentialed CORS behavior. It sends no exploit payloads and submits no forms. The dashboard provides a stop control that cancels between requests; an in-flight request can take up to its configured timeout to finish.
- At most 256 KB of HTML per page, inspected for password forms using GET, password forms posting over HTTP, and executable resources loaded over HTTP.
- SPF and DMARC TXT records. DKIM lookup checks a small set of common selectors; no selector found does not prove that DKIM is absent.
- Reports up to five redirects, but stops before following a redirect to a different hostname. Authorize and scan that hostname separately if appropriate.

The scanner never submits forms, fuzzes inputs, sends exploit payloads, or tests application code and business logic. Authenticated role and business-logic testing still requires owner-supplied test accounts and manual assessment. An optional bearer token is supported for authorized HTTPS scans; it is sent only with HTTPS requests for the scan, cleared from the browser field on submit, and excluded from reports and history. A clean report does not establish that a site is secure. The displayed percentage is a weighted score of checks observed by SecureScan, not the probability of compromise.

Findings have stable identifiers and can be marked open, fixed, accepted, or false positive. A reason is required for false positives. Optional expiry timestamps can be set through the API. Rescans report whether findings marked fixed are still detected. Finding state is kept in the local SQLite database. History can be filtered, viewed, exported as JSON, and deleted per scan or in full. Coverage shows the source and timestamp for each data group; unavailable lookups are identified instead of treated as definitive results.

## Safety and data handling

- Private, loopback, and non-public IP addresses are blocked, including addresses returned by DNS and redirect destinations.
- Connections are pinned to validated public IPs to reduce DNS rebinding risk.
- Each scan is bounded by request timeouts, a five-redirect limit, a ten-page thorough-crawl limit, two sitemap files and at most 100 sitemap URLs considered, a per-response size limit, a single-scan lock, and a 15-second per-host cooldown.
- Scan history is stored in `scan_history.sqlite3` beside the application and retains at most 200 reports. Use **Clear history** in the dashboard to delete saved history.
- `scan_report.json` and `scan_report.txt` are also written in the process working directory as the latest scan artifacts.

For production use, add authentication, review network exposure, and configure appropriate access controls. The dashboard acknowledgment is not a substitute for access control.

## Tests

Run the test suite from the project directory:

```powershell
python -m pytest -q
```
