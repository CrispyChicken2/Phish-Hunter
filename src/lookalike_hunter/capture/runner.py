"""Visit the alerts waiting for a capture, one site at a time."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

import duckdb

from lookalike_hunter.capture.browser import BrowserCapturer
from lookalike_hunter.capture.models import CaptureStatus
from lookalike_hunter.config import CaptureConfig
from lookalike_hunter.ingest.store import LockContentionError, MatchStore, PendingCapture
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


@dataclass
class CaptureRunStats:
    attempted: int = 0
    save_failures: int = 0
    by_status: Counter[str] = field(default_factory=Counter)

    @property
    def succeeded(self) -> int:
        return self.by_status[str(CaptureStatus.OK)]


async def run_captures(
    store: MatchStore,
    config: CaptureConfig,
    limit: int | None = None,
    targets: Sequence[PendingCapture] | None = None,
) -> CaptureRunStats:
    """Capture pending alerts sequentially.

    Sequential on purpose: these are hostile sites, and one browser context at a
    time keeps resource use predictable and the logs readable.
    """
    pending = (
        list(targets)
        if targets is not None
        else store.pending_captures(limit or config.max_per_run, config.recapture_after_h)
    )
    stats = CaptureRunStats()
    if not pending:
        log.info("capture.nothing_pending")
        return stats

    log.info("capture.start", pending=len(pending))
    async with BrowserCapturer(config) as capturer:
        for target in pending:
            result = await capturer.capture(target.fqdn)
            stats.attempted += 1
            stats.by_status[str(result.status)] += 1
            try:
                store.save_capture(result)
            except (LockContentionError, duckdb.Error) as exc:
                # The screenshot is already on disk; losing the row is bad but it
                # must not cost us the rest of the batch.
                stats.save_failures += 1
                log.error("capture.save_failed", fqdn=target.fqdn, error=str(exc)[:300])
                continue
            log.info(
                "capture.done",
                fqdn=target.fqdn,
                brand=target.brand,
                score=target.score,
                status=str(result.status),
                http_status=result.http_status,
                final_url=result.final_url,
                login_form=result.signals.has_login_form if result.signals else None,
                duration_ms=result.duration_ms,
                error=result.error,
            )
    log.info(
        "capture.finished",
        attempted=stats.attempted,
        save_failures=stats.save_failures,
        **dict(stats.by_status),
    )
    return stats
