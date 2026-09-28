"""Where an Alert goes once the pipeline decides it is worth a human's attention.

Two sinks: a file, which needs nothing and works offline, and a webhook, which
posts JSON and therefore works with Slack, Discord, Teams or anything else that
accepts one.

Everything written here contains attacker-controlled text: the hostname, the page
title, the model's evidence sentence. It is escaped before it reaches a terminal
or a chat client, because a notification is read by a person and control
characters are how a crafted page talks to their screen.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

import httpx

from lookalike_hunter.logging import get_logger

log = get_logger(__name__)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(value: object, limit: int = 300) -> str:
    """Strip control characters from attacker-influenced text."""
    return _CONTROL_CHARS.sub(" ", str(value))[:limit]


@dataclass(frozen=True, slots=True)
class Notification:
    """One finding worth telling someone about."""

    fqdn: str
    brand: str
    label: str
    confidence: float
    score: float
    evidence: str
    screenshot: str | None
    final_url: str | None
    detected_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "fqdn": clean(self.fqdn, 253),
            "brand": clean(self.brand, 40),
            "label": clean(self.label, 20),
            "confidence": self.confidence,
            "score": self.score,
            "evidence": clean(self.evidence, 500),
            "screenshot": clean(self.screenshot, 300) if self.screenshot else None,
            "final_url": clean(self.final_url, 500) if self.final_url else None,
            "detected_at": self.detected_at.isoformat(),
        }

    def as_text(self) -> str:
        """A one-screen summary. The URL is defanged so nobody clicks it by reflex."""
        lines = [
            f"[{clean(self.label, 20)}] {clean(self.fqdn, 253)} "
            f"(brand: {clean(self.brand, 40)}, confidence {self.confidence:.2f}, "
            f"score {self.score:.2f})",
            f"evidence: {clean(self.evidence, 500)}",
        ]
        if self.final_url:
            lines.append(f"final URL: {defang(self.final_url)}")
        if self.screenshot:
            lines.append(f"screenshot: {clean(self.screenshot, 300)}")
        return "\n".join(lines)


def defang(url: str) -> str:
    """Render a hostile URL unclickable, the way threat reports do.

    A notification lands in a chat client that turns URLs into links. One mistaken
    click opens the phishing page in someone's everyday browser, outside the
    container this project is careful to use.
    """
    return (
        clean(url, 500)
        .replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


class AlertSink(Protocol):
    name: str

    def send(self, notification: Notification) -> None: ...


class FileSink:
    """Append one JSON object per notification. The default: no network, no account."""

    name = "file"

    def __init__(self, path: Path) -> None:
        self.path = path

    def send(self, notification: Notification) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(notification.as_dict(), sort_keys=True) + "\n")


class WebhookSink:
    """POST the notification as JSON.

    The payload carries both a `text` field, which Slack, Discord and Teams all
    render, and the structured fields, so a custom consumer need not parse prose.
    """

    name = "webhook"

    def __init__(self, url: str, timeout_s: float = 15.0, client: httpx.Client | None = None):
        self.url = url
        self._timeout = timeout_s
        self._client = client

    def send(self, notification: Notification) -> None:
        payload = {"text": notification.as_text(), **notification.as_dict()}
        client = self._client or httpx.Client(timeout=self._timeout)
        try:
            response = client.post(self.url, json=payload, timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # A failed notification must not lose the finding: it stays unsent and
            # the next run retries it.
            raise AlertDeliveryError(f"webhook delivery failed: {exc}") from exc
        finally:
            if self._client is None:
                client.close()


class AlertDeliveryError(RuntimeError):
    """The notification could not be delivered and should be retried."""
