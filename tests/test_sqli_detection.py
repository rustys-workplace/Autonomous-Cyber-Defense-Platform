"""
Active SQL Injection engine tests.

Spins up a local, intentionally-vulnerable HTTP server that emulates the three
classes of SQLi the engine must catch, plus a safe endpoint that must NOT be
flagged (false-positive guard). No external network is used.
"""
import re
import time
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tools.vuln_scanner_mcp import active_sqli_scan, tool_scan_sqli_live
from tools.safety import SafetyValidator


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        idv = qs.get("id", [""])[0]
        norm = idv.replace(" ", "").lower()

        if path == "/error.php":
            # Verbose DB error on an unbalanced quote (classic error-based).
            if idv.count("'") % 2 == 1:
                return self._send(
                    "<b>Warning</b>: You have an error in your SQL syntax; check the "
                    "manual that corresponds to your MySQL server version near \"'\"", 200)
            return self._send(f"<html>Product {idv or '1'} — Acme Widget, $9.99</html>")

        if path == "/bool.php":
            # No error text ever; content depends only on the boolean condition.
            is_false = ("'1'='2" in norm) or ("1=2" in norm) or ("')and('1'='2" in norm)
            if is_false:
                return self._send("<html><body>No results found.</body></html>")
            return self._send(
                "<html><body><h1>Acme Widget</h1><p>In stock. Ships today. "
                "Full product catalog row with lots of stable content here.</p></body></html>")

        if path == "/time.php":
            # No error, no boolean differential; only a real injected delay.
            m = re.search(r"(?:sleep|pg_sleep)\((\d+)\)", norm) or re.search(r"delay'0:0:(\d+)", norm)
            if m:
                time.sleep(min(int(m.group(1)), 3))
            return self._send("<html>OK</html>")

        if path == "/safe.php":
            # Parameterized backend: identical response regardless of input.
            return self._send("<html><body>Welcome. Static page.</body></html>")

        return self._send("not found", 404)


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


@pytest.mark.asyncio
async def test_error_based_sqli(server):
    findings = await active_sqli_scan(f"{server}/error.php?id=1",
                                      endpoints=[f"{server}/error.php?id=1"],
                                      enable_time_based=False)
    assert findings, "error-based SQLi not detected"
    assert findings[0]["detection_method"] == "error-based"
    assert findings[0]["cwe_id"] == "CWE-89"
    assert findings[0]["parameter"] == "id"


@pytest.mark.asyncio
async def test_boolean_blind_sqli(server):
    findings = await active_sqli_scan(f"{server}/bool.php?id=1",
                                      endpoints=[f"{server}/bool.php?id=1"],
                                      enable_time_based=False)
    assert findings, "boolean-blind SQLi not detected"
    assert findings[0]["detection_method"] == "boolean-blind"
    assert findings[0]["active_confirmed"] is True


@pytest.mark.asyncio
async def test_time_based_sqli(server):
    findings = await active_sqli_scan(f"{server}/time.php?id=1",
                                      endpoints=[f"{server}/time.php?id=1"],
                                      enable_time_based=True, time_delay=2)
    assert findings, "time-based SQLi not detected"
    assert findings[0]["detection_method"] == "time-based"


@pytest.mark.asyncio
async def test_safe_endpoint_no_false_positive(server):
    findings = await active_sqli_scan(f"{server}/safe.php?id=1",
                                      endpoints=[f"{server}/safe.php?id=1"],
                                      enable_time_based=True, time_delay=2)
    assert findings == [], f"false positive on safe endpoint: {findings}"


@pytest.mark.asyncio
async def test_mcp_tool_wrapper(server):
    res = await tool_scan_sqli_live(f"{server}/error.php?id=1")
    assert res["vulnerability_detected"] is True
    assert res["count"] >= 1
    assert set(res["techniques"]) == {"error-based", "boolean-blind", "time-based"}


def test_all_engine_payloads_pass_safety_gate():
    # Every payload family the engine can emit must be non-destructive.
    payloads = [
        "1'", "1' AND '1'='1", "1' AND '1'='2", "1') AND ('1'='1", "1 AND 1=1",
        "1' AND SLEEP(3)-- -", "1 AND SLEEP(3)", "1'||pg_sleep(3)-- -",
        "1'; WAITFOR DELAY '0:0:3'-- -",
    ]
    for p in payloads:
        ok, reason = SafetyValidator.validate_payload(p)
        assert ok, f"payload wrongly blocked: {p} -> {reason}"
