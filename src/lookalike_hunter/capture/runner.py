"""Host side of a capture: choose the targets, run the container, import what it saw.

Only this side touches the database. The container gets a job file and writes
screenshots and a results file into the capture directory, its one mount; this
module then validates every line before it becomes a row (see
:mod:`lookalike_hunter.capture.handoff` for what is checked and why).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import duckdb

from lookalike_hunter.capture.handoff import (
    CaptureJob,
    ImportReport,
    import_results,
    job_path,
    new_job,
    results_path,
    write_job,
)
from lookalike_hunter.capture.models import CaptureStatus
from lookalike_hunter.config import CaptureConfig
from lookalike_hunter.ingest.store import LockContentionError, MatchStore, PendingCapture
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)

# Runs the visits for a job, writing results under the capture directory.
Executor = Callable[[CaptureJob, Path], Awaitable[None]]

COMPOSE_SERVICE = "capture"
# Where docker-compose.yml mounts the host's capture directory.
CONTAINER_ROOT = "/app/captures"
# Time for compose to start the container, or build the image on a first run.
STARTUP_ALLOWANCE_S = 600


class CaptureExecutionError(RuntimeError):
    """The visits did not run to completion; whatever was written is still imported."""


@dataclass
class CaptureRunStats:
    attempted: int = 0
    save_failures: int = 0
    rejected: int = 0
    # Targets with no accepted result: the container stopped early or lied.
    missing: int = 0
    by_status: Counter[str] = field(default_factory=Counter)

    @property
    def succeeded(self) -> int:
        return self.by_status[str(CaptureStatus.OK)]


def container_name(job_id: str) -> str:
    return f"lookalike-capture-{job_id}"


def docker_command(job_id: str) -> list[str]:
    """`docker compose run` for one job; named so it can be removed if we give up."""
    return [
        "docker",
        "compose",
        "run",
        "--rm",
        "--name",
        container_name(job_id),
        COMPOSE_SERVICE,
        "visit",
        job_id,
        "--root",
        CONTAINER_ROOT,
    ]


def _deadline_s(job: CaptureJob) -> float:
    per_site = job.config.timeout_s * len(job.config.schemes) + job.config.settle_ms / 1000 + 10
    return STARTUP_ALLOWANCE_S + per_site * len(job.targets)


async def visit_in_docker(job: CaptureJob, root: Path) -> None:
    """Run the job in the hardened capture container (the default)."""
    # docker-compose.yml mounts this directory, and only this one.
    env = {**os.environ, "LH_CAPTURES_DIR": str(root.resolve())}
    try:
        process = await asyncio.create_subprocess_exec(*docker_command(job.job_id), env=env)
    except FileNotFoundError as exc:
        raise CaptureExecutionError(
            "docker is not installed or not on PATH; start Docker, or pass "
            "--outside-container to visit from this machine"
        ) from exc
    try:
        code = await asyncio.wait_for(process.wait(), _deadline_s(job))
    except (TimeoutError, asyncio.CancelledError):
        # `docker compose run` killed from outside can leave the container
        # running a hostile page; remove it by name.
        await _remove_container(job.job_id)
        raise
    if code != 0:
        raise CaptureExecutionError(f"capture container exited with status {code}")


async def _remove_container(job_id: str) -> None:
    process = await asyncio.create_subprocess_exec(
        "docker",
        "rm",
        "-f",
        container_name(job_id),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    await process.wait()


async def visit_in_process(job: CaptureJob, root: Path) -> None:
    """Run the job in this process: no container between the page and this machine."""
    from lookalike_hunter.capture.visit import visit

    await visit(job, root)


async def run_captures(
    store: MatchStore,
    config: CaptureConfig,
    limit: int | None = None,
    targets: Sequence[PendingCapture] | None = None,
    executor: Executor = visit_in_docker,
) -> CaptureRunStats:
    """Capture pending alerts (or ``targets``) and store what passes validation."""
    pending = (
        list(targets)
        if targets is not None
        else store.pending_captures(limit or config.max_per_run, config.recapture_after_h)
    )
    stats = CaptureRunStats()
    if not pending:
        log.info("capture.nothing_pending")
        return stats

    root = config.output_dir
    job = new_job(list(dict.fromkeys(t.fqdn for t in pending)), config)
    write_job(job, root)
    log.info("capture.start", pending=len(job.targets), job=job.job_id)
    try:
        await executor(job, root)
    except CaptureExecutionError as exc:
        log.error("capture.execution_failed", job=job.job_id, error=str(exc))
    finally:
        # Also on Ctrl+C or a timeout: sites already visited are not lost.
        report = import_results(root, job)
        _save(store, report, job, stats)
        _clean_up(root, job, report)
    log.info(
        "capture.finished",
        attempted=stats.attempted,
        save_failures=stats.save_failures,
        rejected=stats.rejected,
        missing=stats.missing,
        **dict(stats.by_status),
    )
    return stats


def _save(store: MatchStore, report: ImportReport, job: CaptureJob, stats: CaptureRunStats) -> None:
    for reason in report.rejected:
        log.warning("capture.result_rejected", job=job.job_id, reason=reason)
    stats.rejected = len(report.rejected)
    stats.missing = len(job.targets) - len(report.results)
    for result in report.results:
        stats.attempted += 1
        stats.by_status[str(result.status)] += 1
        try:
            store.save_capture(result)
        except (LockContentionError, duckdb.Error) as exc:
            # The screenshot is already on disk; losing the row is bad but it
            # must not cost us the rest of the batch.
            stats.save_failures += 1
            log.error("capture.save_failed", fqdn=result.fqdn, error=str(exc)[:300])
            continue
        log.info(
            "capture.done",
            fqdn=result.fqdn,
            status=str(result.status),
            http_status=result.http_status,
            final_url=result.final_url,
            login_form=result.signals.has_login_form if result.signals else None,
            duration_ms=result.duration_ms,
            error=result.error,
        )


def _clean_up(root: Path, job: CaptureJob, report: ImportReport) -> None:
    """Drop the job's files once imported; keep a results file that had rejections."""
    job_path(root, job.job_id).unlink(missing_ok=True)
    results = results_path(root, job.job_id)
    if report.rejected:
        log.warning("capture.results_kept_for_inspection", path=str(results))
    else:
        results.unlink(missing_ok=True)
