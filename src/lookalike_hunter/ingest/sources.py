"""Certificate Transparency message sources: live certstream websocket or JSONL replay."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Protocol

import websockets

from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


class CertSource(Protocol):
    def messages(self) -> AsyncIterator[dict[str, Any]]: ...


def _decode(raw: str | bytes) -> dict[str, Any] | None:
    try:
        message = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("ct.message.invalid_json", error=str(exc))
        return None
    return message if isinstance(message, dict) else None


class CertstreamSource:
    """certstream-compatible websocket, reconnecting with exponential backoff."""

    def __init__(self, url: str, max_backoff_s: float = 60.0) -> None:
        self.url = url
        self.max_backoff_s = max_backoff_s

    async def messages(self) -> AsyncIterator[dict[str, Any]]:
        backoff = min(1.0, self.max_backoff_s)
        while True:
            try:
                async with websockets.connect(self.url, max_size=2**22) as ws:
                    log.info("ct.connected", url=self.url)
                    backoff = min(1.0, self.max_backoff_s)
                    async for raw in ws:
                        if (message := _decode(raw)) is not None:
                            yield message
                log.warning("ct.closed_by_server", url=self.url)
            except (OSError, websockets.WebSocketException) as exc:
                log.warning(
                    "ct.connection_error", url=self.url, error=repr(exc), retry_in_s=backoff
                )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.max_backoff_s)


class ReplaySource:
    """Replay certstream messages recorded one JSON object per line."""

    def __init__(self, path: Path) -> None:
        self.path = path

    async def messages(self) -> AsyncIterator[dict[str, Any]]:
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip() and (message := _decode(line)) is not None:
                    yield message
