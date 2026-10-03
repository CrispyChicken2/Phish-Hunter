"""The container side of a capture: visit the job's hostnames, write what was seen.

No database, no configuration file: the job carries the targets and the capture
settings, and the results go back as files in the capture directory (see
:mod:`lookalike_hunter.capture.handoff`).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from lookalike_hunter.capture.browser import BrowserCapturer
from lookalike_hunter.capture.handoff import CaptureJob, ResultWriter
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


async def visit(job: CaptureJob, root: Path) -> Counter[str]:
    """Visit every target sequentially; returns how many ended in each status.

    Sequential on purpose: these are hostile sites, and one browser context at a
    time keeps resource use predictable and the logs readable.
    """
    config = job.config.model_copy(update={"output_dir": root})
    writer = ResultWriter(root, job.job_id)
    by_status: Counter[str] = Counter()
    log.info("visit.start", job=job.job_id, targets=len(job.targets))
    async with BrowserCapturer(config) as capturer:
        for fqdn in job.targets:
            result = await capturer.capture(fqdn)
            writer.write(result)
            by_status[str(result.status)] += 1
            log.info(
                "visit.done",
                fqdn=fqdn,
                status=str(result.status),
                http_status=result.http_status,
                final_url=result.final_url,
                duration_ms=result.duration_ms,
                error=result.error,
            )
    log.info("visit.finished", job=job.job_id, **dict(by_status))
    return by_status
