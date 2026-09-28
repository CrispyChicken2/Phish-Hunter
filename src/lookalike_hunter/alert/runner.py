"""Decide which Verdicts are worth a human's attention, and notify once.

Two rules shape this. Only phishing is notified: the pipeline's own measurement
showed most Alerts are parking pages, and a queue full of those is exactly the
noise this project exists to remove. And a finding is announced once, because an
alerting tool that repeats itself gets muted, after which it may as well not run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from lookalike_hunter.alert.sinks import (
    AlertDeliveryError,
    AlertSink,
    FileSink,
    Notification,
    WebhookSink,
)
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


@dataclass
class AlertRunStats:
    considered: int = 0
    sent: int = 0
    failed: int = 0
    by_sink: dict[str, int] = field(default_factory=dict)


def run_alerts(
    store: MatchStore,
    sinks: list[AlertSink],
    min_confidence: float,
    limit: int,
    labels: tuple[str, ...] = ("phishing",),
) -> AlertRunStats:
    """Notify about new Verdicts matching the policy, then record them as sent."""
    stats = AlertRunStats()
    if not sinks:
        log.warning("alert.no_sinks_configured")
        return stats

    pending = store.pending_alerts(labels, min_confidence, limit)
    stats.considered = len(pending)
    if not pending:
        log.info("alert.nothing_to_send")
        return stats

    for row in pending:
        notification = Notification(
            fqdn=row.fqdn,
            brand=row.brand or "unknown",
            label=row.label,
            confidence=row.confidence,
            score=row.score,
            evidence=row.evidence or "",
            screenshot=row.screenshot_path,
            final_url=row.final_url,
            detected_at=row.classified_at,
        )
        delivered_by: list[str] = []
        for sink in sinks:
            try:
                sink.send(notification)
            except AlertDeliveryError as exc:
                stats.failed += 1
                log.error("alert.delivery_failed", sink=sink.name, fqdn=row.fqdn, error=str(exc))
                continue
            delivered_by.append(sink.name)
            stats.by_sink[sink.name] = stats.by_sink.get(sink.name, 0) + 1

        if delivered_by:
            # Marked only after a sink accepted it: a finding nobody received must
            # stay pending rather than be silently forgotten.
            store.mark_alerted(row.verdict_id, datetime.now(row.classified_at.tzinfo))
            stats.sent += 1
            log.info("alert.sent", fqdn=row.fqdn, label=row.label, sinks=delivered_by)

    log.info("alert.finished", considered=stats.considered, sent=stats.sent, failed=stats.failed)
    return stats


def build_sinks(file_path: Path | None, webhook_url: str | None) -> list[AlertSink]:
    """Assemble the configured sinks; the file sink is the default that always works."""
    sinks: list[AlertSink] = []
    if file_path is not None:
        sinks.append(FileSink(file_path))
    if webhook_url:
        sinks.append(WebhookSink(webhook_url))
    return sinks
