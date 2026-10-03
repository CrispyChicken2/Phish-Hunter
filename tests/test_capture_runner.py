"""Host side of a capture: the job goes out, only validated results come back in."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import pytest

import lookalike_hunter.capture.runner as runner
from lookalike_hunter.capture.handoff import (
    CaptureJob,
    ResultWriter,
    job_path,
    new_job,
    results_path,
)
from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.runner import (
    CaptureExecutionError,
    docker_command,
    run_captures,
    visit_in_docker,
)
from lookalike_hunter.config import CaptureConfig
from lookalike_hunter.ingest.store import MatchStore, PendingCapture

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
TARGETS = [PendingCapture("evil.test", "evil.test", "paypal", 0.9)]


def timeout_result(fqdn: str) -> CaptureResult:
    return CaptureResult(fqdn, f"https://{fqdn}/", CaptureStatus.TIMEOUT, NOW, 15000)


def captured_hosts(store: MatchStore) -> list[str]:
    with duckdb.connect(str(store.db_path), read_only=True) as con:
        rows = con.execute("SELECT fqdn FROM captures ORDER BY fqdn").fetchall()
    return [row[0] for row in rows]


@pytest.fixture
def store(tmp_path: Path) -> MatchStore:
    return MatchStore(tmp_path / "t.duckdb", 0.7)


@pytest.fixture
def config(tmp_path: Path) -> CaptureConfig:
    return CaptureConfig(output_dir=tmp_path / "captures")


async def test_a_container_cannot_add_captures_it_was_not_asked_for(
    store: MatchStore, config: CaptureConfig
) -> None:
    async def lying_container(job: CaptureJob, root: Path) -> None:
        writer = ResultWriter(root, job.job_id)
        writer.write(timeout_result("evil.test"))
        writer.write(timeout_result("paypal.com"))  # never requested

    stats = await run_captures(store, config, targets=TARGETS, executor=lying_container)

    assert captured_hosts(store) == ["evil.test"]
    assert stats.attempted == 1 and stats.rejected == 1


async def test_a_clean_run_leaves_no_job_files_behind(
    store: MatchStore, config: CaptureConfig
) -> None:
    jobs: list[CaptureJob] = []

    async def container(job: CaptureJob, root: Path) -> None:
        jobs.append(job)
        ResultWriter(root, job.job_id).write(timeout_result("evil.test"))

    await run_captures(store, config, targets=TARGETS, executor=container)

    assert not job_path(config.output_dir, jobs[0].job_id).exists()
    assert not results_path(config.output_dir, jobs[0].job_id).exists()


async def test_results_with_rejections_are_kept_for_inspection(
    store: MatchStore, config: CaptureConfig
) -> None:
    jobs: list[CaptureJob] = []

    async def container(job: CaptureJob, root: Path) -> None:
        jobs.append(job)
        ResultWriter(root, job.job_id).write(timeout_result("someone-else.test"))

    await run_captures(store, config, targets=TARGETS, executor=container)

    assert results_path(config.output_dir, jobs[0].job_id).exists()


async def test_what_was_visited_before_a_crash_is_still_imported(
    store: MatchStore, config: CaptureConfig
) -> None:
    two = [*TARGETS, PendingCapture("second.test", "second.test", "paypal", 0.8)]

    async def crashing_container(job: CaptureJob, root: Path) -> None:
        ResultWriter(root, job.job_id).write(timeout_result("evil.test"))
        raise CaptureExecutionError("capture container exited with status 137")

    stats = await run_captures(store, config, targets=two, executor=crashing_container)

    assert captured_hosts(store) == ["evil.test"]
    assert stats.missing == 1


async def test_an_interrupted_run_still_imports_then_stops(
    store: MatchStore, config: CaptureConfig
) -> None:
    async def interrupted(job: CaptureJob, root: Path) -> None:
        ResultWriter(root, job.job_id).write(timeout_result("evil.test"))
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await run_captures(store, config, targets=TARGETS, executor=interrupted)

    assert captured_hosts(store) == ["evil.test"]


async def test_nothing_pending_starts_no_container(
    store: MatchStore, config: CaptureConfig
) -> None:
    async def must_not_run(job: CaptureJob, root: Path) -> None:
        raise AssertionError("no container should be started")

    stats = await run_captures(store, config, executor=must_not_run)

    assert stats.attempted == 0


# ---------------------------------------------------------------------- docker


def test_the_container_is_disposable_and_named() -> None:
    command = docker_command("20261003t090000z-abcd1234")

    assert command[:4] == ["docker", "compose", "run", "--rm"]
    assert "lookalike-capture-20261003t090000z-abcd1234" in command
    assert command[-4:] == ["visit", "20261003t090000z-abcd1234", "--root", "/app/captures"]


class FakeProcess:
    def __init__(self, code: int = 0, hang: bool = False) -> None:
        self.code = code
        self.hang = hang

    async def wait(self) -> int:
        if self.hang:
            await asyncio.sleep(3600)
        return self.code


def fake_exec(
    monkeypatch: pytest.MonkeyPatch, process: FakeProcess
) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    async def create(*args: str, **kwargs: Any) -> FakeProcess:
        calls.append((args, kwargs))
        return process if args[1] == "compose" else FakeProcess()

    monkeypatch.setattr("asyncio.create_subprocess_exec", create)
    return calls


async def test_docker_mounts_the_configured_capture_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = fake_exec(monkeypatch, FakeProcess())

    await visit_in_docker(new_job(["evil.test"], CaptureConfig()), tmp_path)

    assert calls[0][1]["env"]["LH_CAPTURES_DIR"] == str(tmp_path.resolve())


async def test_a_failed_container_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, FakeProcess(code=1))

    with pytest.raises(CaptureExecutionError, match="status 1"):
        await visit_in_docker(new_job(["evil.test"], CaptureConfig()), Path())


async def test_a_container_that_overruns_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Killing `docker compose run` can leave the container running a hostile page."""
    calls = fake_exec(monkeypatch, FakeProcess(hang=True))
    monkeypatch.setattr(runner, "STARTUP_ALLOWANCE_S", 0)
    job = new_job([], CaptureConfig())

    with pytest.raises(TimeoutError):
        await visit_in_docker(job, Path())

    assert calls[-1][0] == ("docker", "rm", "-f", f"lookalike-capture-{job.job_id}")


async def test_missing_docker_says_what_to_do(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_docker(*args: str, **kwargs: Any) -> None:
        raise FileNotFoundError("docker")

    monkeypatch.setattr("asyncio.create_subprocess_exec", no_docker)

    with pytest.raises(CaptureExecutionError, match="--outside-container"):
        await visit_in_docker(new_job(["evil.test"], CaptureConfig()), Path())
