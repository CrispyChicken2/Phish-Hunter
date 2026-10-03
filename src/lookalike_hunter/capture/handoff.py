"""The files the host and the capture container exchange, and the checks on the way back.

The container runs attacker code, so it is given nothing it does not need: no
database, no configuration directory, no dataset. It receives a job file listing
the hostnames to visit and returns screenshots plus one results file, all inside
the capture directory, the only host path it can write.

Everything that comes back is treated as written by an attacker who escaped the
browser, because that is the case this split exists for. A result is accepted
only for a hostname the job asked about, once, with every field typed and
bounded, and with a screenshot that is a real PNG inside the capture directory.
Anything else is rejected and logged, never written to the database.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus, stored_capture_file
from lookalike_hunter.capture.policy import candidate_urls
from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.config import CaptureConfig

JOBS_DIR = "_jobs"
RESULTS_DIR = "_results"

# A run of max_per_run sites produces a few kilobytes; anything near this is not
# a results file, and reading it would only cost the host memory.
MAX_RESULTS_BYTES = 5_000_000
MAX_SCREENSHOT_BYTES = 30_000_000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

_JOB_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")


class CaptureJob(BaseModel):
    """What the host asks the container to visit, and how."""

    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(pattern=_JOB_ID_RE.pattern)
    targets: list[str]
    # output_dir is ignored on the container side: it writes to its own mount.
    config: CaptureConfig


def new_job(targets: list[str], config: CaptureConfig) -> CaptureJob:
    stamp = datetime.now(UTC).strftime("%Y%m%dt%H%M%Sz")
    return CaptureJob(job_id=f"{stamp}-{uuid.uuid4().hex[:8]}", targets=targets, config=config)


def job_path(root: Path, job_id: str) -> Path:
    if not _JOB_ID_RE.match(job_id):
        raise ValueError(f"not a job id: {job_id[:80]!r}")
    return root / JOBS_DIR / f"{job_id}.json"


def results_path(root: Path, job_id: str) -> Path:
    if not _JOB_ID_RE.match(job_id):
        raise ValueError(f"not a job id: {job_id[:80]!r}")
    return root / RESULTS_DIR / f"{job_id}.jsonl"


def write_job(job: CaptureJob, root: Path) -> Path:
    path = job_path(root, job.job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(job.model_dump_json(), encoding="utf-8")
    return path


def read_job(root: Path, job_id: str) -> CaptureJob:
    return CaptureJob.model_validate_json(job_path(root, job_id).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- container side


class ResultWriter:
    """Append one JSON line per visit, flushed each time.

    A crash or a browser that hangs mid-batch then still leaves the sites
    already visited for the host to import.
    """

    def __init__(self, root: Path, job_id: str) -> None:
        self.path = results_path(root, job_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, result: CaptureResult) -> None:
        record = {
            "fqdn": result.fqdn,
            "url": result.url,
            "status": str(result.status),
            "captured_at": result.captured_at.isoformat(),
            "duration_ms": result.duration_ms,
            "final_url": result.final_url,
            "http_status": result.http_status,
            "screenshot_path": _posix(result.screenshot_path),
            "html_path": _posix(result.html_path),
            "signals": asdict(result.signals) if result.signals else None,
            "error": result.error,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


def _posix(path: Path | None) -> str | None:
    return path.as_posix() if path is not None else None


# --------------------------------------------------------------------- host side


class _SignalsRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, max_length=300)
    form_count: int = Field(ge=0, le=10_000)
    has_password_input: bool
    has_credential_field: bool
    cross_domain_form_targets: list[Annotated[str, Field(max_length=253)]] = Field(max_length=50)
    iframe_count: int = Field(ge=0, le=10_000)
    password_input_count: int = Field(ge=0, le=10_000)


class _ResultRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fqdn: str = Field(max_length=300)
    url: str = Field(max_length=2100)
    status: CaptureStatus
    captured_at: AwareDatetime
    duration_ms: int = Field(ge=0, le=86_400_000)
    final_url: str | None = Field(default=None, max_length=2100)
    http_status: int | None = Field(default=None, ge=100, le=599)
    screenshot_path: str | None = Field(default=None, max_length=300)
    html_path: str | None = Field(default=None, max_length=300)
    signals: _SignalsRecord | None = None
    error: str | None = Field(default=None, max_length=2000)


@dataclass
class ImportReport:
    results: list[CaptureResult] = field(default_factory=list)
    # One human-readable reason per refused line, for the log.
    rejected: list[str] = field(default_factory=list)


def import_results(root: Path, job: CaptureJob) -> ImportReport:
    """Validate what the container returned for ``job``. Never raises on bad content."""
    report = ImportReport()
    path = results_path(root, job.job_id)
    base = root.resolve()
    if not path.exists() and not path.is_symlink():
        return report
    # A symlink would have the host read a file of the container's choosing.
    if path.is_symlink() or not path.resolve().is_relative_to(base) or not path.is_file():
        report.rejected.append("results file is not a regular file in the capture directory")
        return report
    if path.stat().st_size > MAX_RESULTS_BYTES:
        report.rejected.append(f"results file larger than {MAX_RESULTS_BYTES} bytes")
        return report

    expected = set(job.targets)
    seen: set[str] = set()
    text = path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = _ResultRecord.model_validate_json(line)
        except ValidationError as exc:
            report.rejected.append(f"line {number}: {exc.error_count()} invalid field(s)")
            continue
        reason = _refusal(record, root, job, expected, seen)
        if reason is not None:
            report.rejected.append(f"line {number}: {reason}")
            continue
        seen.add(record.fqdn)
        report.results.append(_to_result(record, root))
    return report


def _refusal(
    record: _ResultRecord, root: Path, job: CaptureJob, expected: set[str], seen: set[str]
) -> str | None:
    if record.fqdn not in expected:
        return "hostname the job did not ask for"
    if record.fqdn in seen:
        return "second result for the same hostname"
    if record.url not in candidate_urls(record.fqdn, job.config.schemes):
        return "URL is not one this hostname would be visited at"
    if record.status is CaptureStatus.OK:
        shot = _screenshot(record.screenshot_path, root)
        if shot is None:
            return "screenshot missing, outside the capture directory or not a PNG"
    return None


def _screenshot(stored: str | None, root: Path) -> Path | None:
    resolved = stored_capture_file(stored, root)
    if resolved is None or not resolved.is_file():
        return None
    if resolved.stat().st_size > MAX_SCREENSHOT_BYTES:
        return None
    with resolved.open("rb") as handle:
        if handle.read(len(PNG_SIGNATURE)) != PNG_SIGNATURE:
            return None
    return resolved


def _relative(stored: str | None, root: Path) -> Path | None:
    """The stored path, normalised relative to the capture directory, or None."""
    resolved = stored_capture_file(stored, root)
    return resolved.relative_to(root.resolve()) if resolved is not None else None


def _to_result(record: _ResultRecord, root: Path) -> CaptureResult:
    ok = record.status is CaptureStatus.OK
    signals = record.signals
    return CaptureResult(
        fqdn=record.fqdn,
        url=record.url,
        status=record.status,
        captured_at=record.captured_at,
        duration_ms=record.duration_ms,
        final_url=record.final_url,
        http_status=record.http_status,
        # Paths only for a successful visit, and only ones that stay inside.
        screenshot_path=_relative(record.screenshot_path, root) if ok else None,
        html_path=_relative(record.html_path, root) if ok else None,
        signals=PageSignals(**signals.model_dump()) if signals is not None else None,
        error=record.error,
    )
