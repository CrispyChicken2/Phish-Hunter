"""Contention handling: DuckDB allows one writer, and we collect while ingesting."""

import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

from lookalike_hunter.ingest.store import LockContentionError, connect_with_retry


class _Flaky:
    """Fails with a lock error N times, then succeeds."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0

    def __call__(self, path: str, **kwargs: object) -> object:
        self.calls += 1
        if self.calls <= self.failures:
            raise duckdb.IOException(f'Cannot open file "{path}": Permission denied')
        return "connection"


def test_retries_until_the_lock_is_released(tmp_path: Path) -> None:
    connect = _Flaky(failures=2)

    result = connect_with_retry(tmp_path / "t.duckdb", connect=connect, attempts=5, base_delay_s=0)

    assert result == "connection"
    assert connect.calls == 3


def test_gives_up_after_the_configured_attempts(tmp_path: Path) -> None:
    connect = _Flaky(failures=99)

    with pytest.raises(LockContentionError) as excinfo:
        connect_with_retry(tmp_path / "t.duckdb", connect=connect, attempts=3, base_delay_s=0)

    assert connect.calls == 3
    assert "t.duckdb" in str(excinfo.value)


def test_unrelated_io_errors_are_not_retried(tmp_path: Path) -> None:
    def broken(path: str, **kwargs: object) -> object:
        raise duckdb.IOException("Database is corrupted")

    with pytest.raises(duckdb.IOException, match="corrupted"):
        connect_with_retry(tmp_path / "t.duckdb", connect=broken, attempts=3, base_delay_s=0)


def test_real_contention_from_another_process(tmp_path: Path) -> None:
    """The lock is per process: two connections inside one process do not contend.

    This is the case that actually broke collection, so it is worth exercising for
    real rather than against a fake.
    """
    db = tmp_path / "t.duckdb"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import duckdb,sys,time;"
            f"con=duckdb.connect(r'{db}');"
            "con.execute('CREATE TABLE t (x INTEGER)');"
            "print('held', flush=True);"
            "time.sleep(30)",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"  # lock is now taken

        with pytest.raises(LockContentionError, match="locked by another process"):
            connect_with_retry(db, attempts=2, base_delay_s=0.01)
    finally:
        holder.kill()
        holder.wait(timeout=10)

    # Once the other process is gone, the same call succeeds.
    con = connect_with_retry(db, attempts=5, base_delay_s=0.05)
    con.close()


async def test_one_failed_save_does_not_abandon_the_batch(tmp_path: Path) -> None:
    """Contention on site 2 must not cost us site 3 onwards."""
    from datetime import UTC, datetime

    from lookalike_hunter.capture.handoff import CaptureJob, ResultWriter
    from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
    from lookalike_hunter.capture.runner import run_captures
    from lookalike_hunter.config import CaptureConfig
    from lookalike_hunter.ingest.store import MatchStore, PendingCapture

    saved: list[str] = []

    class FlakyStore(MatchStore):
        def __init__(self) -> None:  # no database needed
            self.db_path = tmp_path / "unused.duckdb"
            self.alert_threshold = 0.7

        def pending_captures(self, limit: int, recapture_after_h: float) -> list[PendingCapture]:
            return [
                PendingCapture(f"site{i}.test", f"site{i}.test", "paypal", 0.9) for i in range(3)
            ]

        def save_capture(self, result: CaptureResult) -> None:
            if result.fqdn == "site1.test":
                raise LockContentionError("locked by another process")
            saved.append(result.fqdn)

    async def container(job: CaptureJob, root: Path) -> None:
        writer = ResultWriter(root, job.job_id)
        for fqdn in job.targets:
            writer.write(
                CaptureResult(fqdn, f"https://{fqdn}/", CaptureStatus.TIMEOUT, datetime.now(UTC), 5)
            )

    stats = await run_captures(FlakyStore(), CaptureConfig(output_dir=tmp_path), executor=container)

    assert stats.attempted == 3
    assert stats.save_failures == 1
    assert saved == ["site0.test", "site2.test"]  # the batch continued past the failure
