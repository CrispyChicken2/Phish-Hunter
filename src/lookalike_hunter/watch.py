"""Run the whole pipeline unattended: ingest continuously, triage on a timer.

Ingestion streams Certificate Transparency without pause. Every cycle, the new
Alerts are captured, classified and, if phishing, announced. Phishing kits live
for hours, so the cycle interval is effectively the detection latency: the
evaluation lost most of its phishing sites to takedowns that beat the capture.

Everything runs on one event loop in one process. DuckDB allows a single writer
per file; the store calls are synchronous, so no two of them ever overlap.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Sequence
from dataclasses import dataclass

from lookalike_hunter.alert.runner import run_alerts
from lookalike_hunter.alert.sinks import AlertSink
from lookalike_hunter.capture.runner import Executor, run_captures
from lookalike_hunter.classify.base import Classifier
from lookalike_hunter.classify.runner import run_classifications
from lookalike_hunter.config import Settings
from lookalike_hunter.ingest.pipeline import run_pipeline
from lookalike_hunter.ingest.sources import CertSource
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.logging import get_logger
from lookalike_hunter.scoring.scorer import Scorer

log = get_logger(__name__)


class IngestionStoppedError(RuntimeError):
    """The CT stream ended or failed; without it the watch has nothing to triage."""


@dataclass
class CycleStats:
    captured: int = 0
    classified: int = 0
    notified: int = 0
    # Stages that raised: a failing stage is logged and skipped, never fatal.
    failed_stages: int = 0


async def run_cycle(
    settings: Settings,
    store: MatchStore,
    executor: Executor,
    classifier: Classifier,
    model: str | None,
    sinks: Sequence[AlertSink],
) -> CycleStats:
    """Capture new Alerts, classify the captures, announce phishing. One pass."""
    stats = CycleStats()
    try:
        captured = await run_captures(store, settings.capture, executor=executor)
        stats.captured = captured.attempted
    except Exception:
        stats.failed_stages += 1
        log.exception("watch.capture_failed")
    try:
        classified = await run_classifications(
            store,
            classifier,
            model,
            settings.classify.max_per_run,
            settings.classify.max_retries,
            settings.capture.output_dir,
            settings.classify.min_interval_s,
            settings.classify.retry_base_delay_s,
        )
        stats.classified = classified.classified
    except Exception:
        stats.failed_stages += 1
        log.exception("watch.classify_failed")
    try:
        notified = run_alerts(
            store,
            list(sinks),
            settings.alert.min_confidence,
            settings.alert.max_per_run,
            tuple(settings.alert.labels),
        )
        stats.notified = notified.sent
    except Exception:
        stats.failed_stages += 1
        log.exception("watch.alert_failed")
    log.info("watch.cycle", **vars(stats))
    return stats


async def watch(
    settings: Settings,
    store: MatchStore,
    scorer: Scorer,
    source: CertSource | None,
    executor: Executor,
    classifier: Classifier,
    model: str | None,
    sinks: Sequence[AlertSink],
    interval_s: float,
    cycles: int | None = None,
) -> int:
    """Ingest from ``source`` (if any) while running a triage cycle every ``interval_s``.

    The first cycle runs at once, to work through whatever is already pending.
    ``cycles`` bounds the run (tests, cron); None runs until interrupted. Returns
    the number of cycles completed.
    """
    ingest: asyncio.Task[object] | None = None
    if source is not None:
        ingest = asyncio.create_task(
            run_pipeline(
                source,
                scorer,
                store,
                settings.ct.flush_interval_s,
                settings.ct.flush_max_rows,
            )
        )
    completed = 0
    log.info("watch.start", interval_s=interval_s, ingest=source is not None, cycles=cycles)
    try:
        while cycles is None or completed < cycles:
            _raise_if_stopped(ingest)
            await run_cycle(settings, store, executor, classifier, model, sinks)
            completed += 1
            if cycles is not None and completed >= cycles:
                break
            await asyncio.sleep(interval_s)
    finally:
        if ingest is not None and not ingest.done():
            # Cancellation runs the pipeline's final flush: nothing buffered is lost.
            ingest.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ingest
    return completed


def _raise_if_stopped(ingest: asyncio.Task[object] | None) -> None:
    if ingest is None or not ingest.done():
        return
    error = ingest.exception()
    raise IngestionStoppedError(
        f"certificate ingestion stopped: {error!r}" if error else "certificate stream ended"
    ) from error
