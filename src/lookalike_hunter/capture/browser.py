"""Passive capture of a suspicious page with headless Chromium.

Passive means: we load the page, take a screenshot and read the DOM. We never fill
a form, never submit credentials, never accept a download and never follow a link.
Requests are filtered by :mod:`lookalike_hunter.capture.policy` before they leave.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import socket
from dataclasses import replace
from datetime import UTC, datetime
from types import TracebackType
from urllib.parse import urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    Request,
    Route,
    WebSocketRoute,
    async_playwright,
)
from playwright.async_api import (
    Error as PlaywrightError,
)
from playwright.async_api import (
    TimeoutError as PlaywrightTimeout,
)

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.policy import (
    candidate_urls,
    is_blocked_url,
    is_private_address,
    is_valid_hostname,
)
from lookalike_hunter.capture.signals import extract_signals
from lookalike_hunter.config import CaptureConfig
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)

_UNSAFE_PATH_CHARS = re.compile(r"[^a-z0-9._-]+")

_DNS_ERRORS = ("ERR_NAME_NOT_RESOLVED", "ERR_NAME_RESOLUTION_FAILED", "getaddrinfo")
_CONNECTION_ERRORS = (
    "ERR_CONNECTION_REFUSED",
    "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_CLOSED",
    "ERR_CONNECTION_FAILED",
    "ERR_CONNECTION_TIMED_OUT",
    "ERR_ADDRESS_UNREACHABLE",
    "ERR_EMPTY_RESPONSE",
    "ERR_SSL",
    "ERR_CERT",
    "ERR_SOCKET_NOT_CONNECTED",
    "ERR_HTTP2",
    "ERR_QUIC",
)


def safe_dirname(fqdn: str) -> str:
    """Filesystem-safe directory name for a hostname."""
    return _UNSAFE_PATH_CHARS.sub("_", fqdn.lower()).strip("._-")[:100] or "unknown"


def classify_error(message: str) -> CaptureStatus:
    if any(token in message for token in _DNS_ERRORS):
        return CaptureStatus.DNS_ERROR
    if any(token in message for token in _CONNECTION_ERRORS):
        return CaptureStatus.CONNECTION_ERROR
    return CaptureStatus.ERROR


class BrowserCapturer:
    """Reuses one Chromium instance across captures; one fresh context per site."""

    def __init__(self, config: CaptureConfig) -> None:
        self.config = config
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._dns_cache: dict[str, bool] = {}

    async def __aenter__(self) -> BrowserCapturer:
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(
            headless=True,
            # Playwright disables Chromium's own sandbox by default. The renderer is
            # the process that executes attacker-controlled content, so we keep it.
            # In Docker this needs seccomp=unconfined (see docker-compose.yml).
            chromium_sandbox=self.config.chromium_sandbox,
            args=[
                "--disable-background-networking",
                "--no-default-browser-check",
                # WebRTC sends UDP from the network stack where no route handler
                # sees it, so a page could probe the LAN through a STUN server
                # at a private address. A screenshot never needs it.
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ],
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._pw is not None:
            await self._pw.stop()

    async def _host_is_private(self, host: str) -> bool:
        """Resolve a hostname and refuse it when DNS points into a private range."""
        if is_private_address(host):
            return True
        cached = self._dns_cache.get(host)
        if cached is not None:
            return cached
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, proto=socket.IPPROTO_TCP
            )
        except OSError:
            private = False  # unresolvable: let the browser report the DNS failure
        else:
            private = any(is_private_address(str(info[4][0])) for info in infos)
        self._dns_cache[host] = private
        return private

    async def _refusal(self, url: str) -> str | None:
        """Why ``url`` must not be requested, or None. One rule for every channel."""
        reason = is_blocked_url(url, block_private_networks=self.config.block_private_networks)
        if reason is None and self.config.block_private_networks:
            host = urlparse(url).hostname
            if host and await self._host_is_private(host):
                reason = f"private address behind {host}"
        if reason is not None:
            log.debug("capture.request.blocked", url=url[:200], reason=reason)
        return reason

    async def _guard(self, route: Route, request: Request) -> None:
        if await self._refusal(request.url) is not None:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def _guard_websocket(self, ws: WebSocketRoute) -> None:
        # context.route never sees WebSockets: without this handler a page could
        # open ws://192.168.1.1/ and talk to the router (measured, not assumed).
        if await self._refusal(ws.url) is not None:
            await ws.close(code=1008, reason="blocked")
            return
        ws.connect_to_server()

    async def _new_context(self) -> BrowserContext:
        assert self._browser is not None, "use BrowserCapturer as an async context manager"
        context = await self._browser.new_context(
            viewport={
                "width": self.config.viewport_width,
                "height": self.config.viewport_height,
            },
            ignore_https_errors=self.config.ignore_https_errors,
            accept_downloads=False,
            # Service worker requests are not reliably seen by our route filter,
            # so a page could fetch through one; refuse registration entirely.
            service_workers="block",
            user_agent=self.config.user_agent,
            java_script_enabled=True,
        )
        context.set_default_timeout(self.config.timeout_s * 1000)
        await context.route("**/*", self._guard)
        await context.route_web_socket("**/*", self._guard_websocket)
        return context

    async def capture(self, fqdn: str) -> CaptureResult:
        """Visit ``fqdn`` (HTTPS, then HTTP) and return what was observed."""
        if not is_valid_hostname(fqdn):
            return CaptureResult(
                fqdn,
                fqdn,
                CaptureStatus.BLOCKED,
                datetime.now(UTC),
                0,
                error=f"not a plain hostname: {fqdn[:100]!r}",
            )
        attempts: list[CaptureResult] = []
        for url in candidate_urls(fqdn, self.config.schemes):
            result = await self._capture_url(fqdn, url)
            if result.status is CaptureStatus.OK:
                return result
            attempts.append(result)
            if result.status is CaptureStatus.DNS_ERROR:
                break  # the name does not resolve: another scheme will not help
        # Report every scheme that was tried. Keeping only the last one hid why
        # HTTPS failed behind the HTTP fallback's error, which made triage guesswork.
        last = attempts[-1]
        if len(attempts) > 1:
            detail = " | ".join(f"{a.url}: {a.error or a.status}" for a in attempts)
            last = replace(last, error=detail[:500])
        return last

    async def _capture_url(self, fqdn: str, url: str) -> CaptureResult:
        started = datetime.now(UTC)
        clock = asyncio.get_running_loop().time()

        def elapsed_ms() -> int:
            return int((asyncio.get_running_loop().time() - clock) * 1000)

        blocked = is_blocked_url(url, block_private_networks=self.config.block_private_networks)
        if blocked is not None:
            return CaptureResult(
                fqdn, url, CaptureStatus.BLOCKED, started, elapsed_ms(), error=blocked
            )

        context = await self._new_context()
        try:
            page = await context.new_page()
            # Hostile pages love modal dialogs; never let one block the run.
            page.on("dialog", lambda d: asyncio.create_task(d.dismiss()))
            response = await page.goto(
                url, wait_until="domcontentloaded", timeout=self.config.timeout_s * 1000
            )
            await self._settle(page)
            return await self._collect(fqdn, url, page, response, started, elapsed_ms())
        except PlaywrightTimeout as exc:
            return CaptureResult(
                fqdn, url, CaptureStatus.TIMEOUT, started, elapsed_ms(), error=str(exc)[:500]
            )
        except PlaywrightError as exc:
            message = str(exc)
            return CaptureResult(
                fqdn, url, classify_error(message), started, elapsed_ms(), error=message[:500]
            )
        finally:
            await context.close()

    async def _settle(self, page: Page) -> None:
        """Give client-side kits a moment to render, without extending the deadline."""
        # A page that never goes idle is still worth screenshotting.
        with contextlib.suppress(PlaywrightTimeout):
            await page.wait_for_load_state("networkidle", timeout=self.config.settle_ms)
        await page.wait_for_timeout(min(self.config.settle_ms, 2000))

    async def _collect(
        self,
        fqdn: str,
        url: str,
        page: Page,
        response: object,
        started: datetime,
        duration_ms: int,
    ) -> CaptureResult:
        directory = self.config.output_dir / safe_dirname(fqdn)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        screenshot_path = directory / f"{stamp}.png"
        # Not ".html": double-clicking that would run the kit's scripts in the
        # operator's own browser, outside the container, from file://.
        html_path = directory / f"{stamp}.html.txt"

        await page.screenshot(path=str(screenshot_path), full_page=self.config.full_page_screenshot)
        html = (await page.content())[: self.config.max_html_bytes]
        html_path.write_text(html, encoding="utf-8", errors="replace")
        final_url = page.url
        return CaptureResult(
            fqdn=fqdn,
            url=url,
            status=CaptureStatus.OK,
            captured_at=started,
            duration_ms=duration_ms,
            final_url=final_url,
            http_status=getattr(response, "status", None),
            # Stored relative to output_dir: captures are written inside a container
            # and read from the host, where /app/data does not exist.
            screenshot_path=screenshot_path.relative_to(self.config.output_dir),
            html_path=html_path.relative_to(self.config.output_dir),
            signals=extract_signals(html, final_url),
        )
