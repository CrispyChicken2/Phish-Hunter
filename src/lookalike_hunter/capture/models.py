"""Result of one passive visit to a suspicious site."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from lookalike_hunter.capture.signals import PageSignals


class CaptureStatus(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    DNS_ERROR = "dns_error"
    CONNECTION_ERROR = "connection_error"
    # Refused by our own guardrails (private IP, disallowed scheme).
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CaptureResult:
    fqdn: str
    url: str
    status: CaptureStatus
    captured_at: datetime
    duration_ms: int
    final_url: str | None = None
    http_status: int | None = None
    screenshot_path: Path | None = None
    html_path: Path | None = None
    signals: PageSignals | None = None
    error: str | None = None

    @property
    def reachable(self) -> bool:
        return self.status is CaptureStatus.OK
