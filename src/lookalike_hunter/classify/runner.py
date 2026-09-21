"""Classify stored captures and persist one verdict per capture."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.base import (
    ClassificationError,
    ClassificationInput,
    Classifier,
    classify_with_retries,
)
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.ingest.store import MatchStore, PendingClassification
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


@dataclass
class ClassifyRunStats:
    attempted: int = 0
    failed: int = 0
    by_label: Counter[str] = field(default_factory=Counter)
    total_latency_ms: int = 0

    @property
    def classified(self) -> int:
        return self.attempted - self.failed


def _signals_from_row(row: PendingClassification) -> PageSignals | None:
    if row.signals is None:
        return None
    known = {f for f in PageSignals.__dataclass_fields__}
    return PageSignals(**{k: v for k, v in row.signals.items() if k in known})


def _offline_verdict(row: PendingClassification) -> Verdict | None:
    """Verdicts that need no model: an unreachable site, or a missing screenshot."""
    if row.status != "ok":
        return Verdict(
            label=Label.UNREACHABLE,
            confidence=1.0,
            evidence=f"Capture failed with status {row.status}.",
        )
    if row.screenshot_path is None or not row.screenshot_path.exists():
        return Verdict(
            label=Label.UNKNOWN,
            confidence=0.0,
            evidence="Screenshot file is missing; cannot classify.",
        )
    return None


async def run_classifications(
    store: MatchStore,
    classifier: Classifier,
    model: str | None,
    limit: int,
    max_retries: int,
) -> ClassifyRunStats:
    pending = store.pending_classifications(limit, classifier.name)
    stats = ClassifyRunStats()
    if not pending:
        log.info("classify.nothing_pending", backend=classifier.name)
        return stats

    log.info("classify.start", backend=classifier.name, model=model, pending=len(pending))
    for row in pending:
        stats.attempted += 1
        now = datetime.now(UTC)
        offline = _offline_verdict(row)
        if offline is not None:
            store.save_verdict(row.capture_id, row.fqdn, classifier.name, model, offline, now)
            stats.by_label[str(offline.label)] += 1
            continue

        assert row.screenshot_path is not None
        item = ClassificationInput(
            fqdn=row.fqdn,
            suspected_brand=row.suspected_brand,
            screenshot_path=row.screenshot_path,
            final_url=row.final_url,
            signals=_signals_from_row(row),
        )
        started = time.perf_counter()
        try:
            verdict = await classify_with_retries(classifier, item, max_retries)
        except ClassificationError as exc:
            latency = int((time.perf_counter() - started) * 1000)
            stats.failed += 1
            store.save_verdict(
                row.capture_id,
                row.fqdn,
                classifier.name,
                model,
                None,
                now,
                latency,
                str(exc)[:500],
            )
            log.error("classify.failed", fqdn=row.fqdn, error=str(exc)[:300])
            continue

        latency = int((time.perf_counter() - started) * 1000)
        stats.total_latency_ms += latency
        stats.by_label[str(verdict.label)] += 1
        store.save_verdict(row.capture_id, row.fqdn, classifier.name, model, verdict, now, latency)
        log.info(
            "classify.verdict",
            fqdn=row.fqdn,
            label=str(verdict.label),
            confidence=verdict.confidence,
            brand=verdict.brand_impersonated,
            latency_ms=latency,
        )

    log.info(
        "classify.finished",
        attempted=stats.attempted,
        failed=stats.failed,
        **dict(stats.by_label),
    )
    return stats
