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
        """A one-screen summary for a chat client, with nothing in it that acts.

        Every field is made chat-safe, not only the URL: a bare hostname is
        auto-linked too, and the evidence sentence repeats page text, which can
        carry a mention or a disguised link.
        """
        lines = [
            f"[{chat_safe(self.label, 20)}] {chat_safe(self.fqdn, 253)} "
            f"(brand: {chat_safe(self.brand, 40)}, confidence {self.confidence:.2f}, "
            f"score {self.score:.2f})",
            f"evidence: {chat_safe(self.evidence, 500)}",
        ]
        if self.final_url:
            lines.append(f"final URL: {chat_safe(self.final_url, 500)}")
        if self.screenshot:
            lines.append(f"screenshot: {chat_safe(self.screenshot, 300)}")
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


# A dot followed by a letter is how a hostname looks to an auto-linker; "0.93" is
# left alone.
_LINKABLE_DOT = re.compile(r"(?<=[A-Za-z0-9-])\.(?=[A-Za-z])")


def chat_safe(value: object, limit: int = 300) -> str:
    """Attacker-influenced text that a chat client will display but never act on.

    Slack reads ``<!channel>`` and ``<https://evil|your bank>``, Discord reads
    ``@everyone`` and ``[your bank](https://evil)``, and both turn a bare hostname
    into a link. A page whose text reaches the evidence sentence could otherwise
    ping a whole channel or plant a disguised link in the analyst's own alert.
    """
    text = clean(value, limit).replace("http://", "hxxp://").replace("https://", "hxxps://")
    text = _LINKABLE_DOT.sub("[.]", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # A zero-width space after @ keeps the text readable but breaks the mention.
    return text.replace("@", "@​")


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

    The prose goes in `text`, which Slack and Teams render, and again in
    `content`, which is the field Discord reads (it rejects a message without
    one). The structured fields follow, so a custom consumer need not parse prose.

    The URL is a credential: anyone holding a Slack or Discord webhook URL can
    post as it. It is therefore kept out of every error message and log line.
    """

    name = "webhook"

    def __init__(self, url: str, timeout_s: float = 15.0, client: httpx.Client | None = None):
        self.url = url
        self._timeout = timeout_s
        self._client = client

    def send(self, notification: Notification) -> None:
        text = notification.as_text()
        payload = {"text": text, "content": text, **notification.as_dict()}
        client = self._client or httpx.Client(timeout=self._timeout)
        try:
            response = client.post(self.url, json=payload, timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # A failed notification must not lose the finding: it stays unsent and
            # the next run retries it. httpx puts the URL in its own message, so
            # only the status is reported.
            raise AlertDeliveryError(f"webhook answered HTTP {exc.response.status_code}") from None
        except httpx.HTTPError as exc:
            raise AlertDeliveryError(f"webhook delivery failed: {type(exc).__name__}") from None
        finally:
            if self._client is None:
                client.close()


class AlertDeliveryError(RuntimeError):
    """The notification could not be delivered and should be retried."""
