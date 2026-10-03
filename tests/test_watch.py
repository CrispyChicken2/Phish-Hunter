"""The unattended loop: CT in one end, a phishing notification out of the other."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from lookalike_hunter.alert.sinks import FileSink
from lookalike_hunter.capture.handoff import PNG_SIGNATURE, CaptureJob, ResultWriter
from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.base import StubClassifier
from lookalike_hunter.config import AlertConfig, CaptureConfig, ClassifyConfig, CTConfig, Settings
from lookalike_hunter.ingest.pipeline import run_pipeline
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex
from lookalike_hunter.watch import IngestionStoppedError, run_cycle, watch

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "certstream_sample.jsonl"


class StreamThenWait:
    """A CT source that delivers the fixture, then stays connected and quiet."""

    def __init__(self, end: bool = False) -> None:
        self.end = end

    async def messages(self) -> AsyncIterator[dict[str, Any]]:
        for line in FIXTURE.read_text(encoding="utf-8").splitlines():
            if line.strip():
                yield json.loads(line)
        if not self.end:
            await asyncio.Event().wait()


async def phishing_kit_everywhere(job: CaptureJob, root: Path) -> None:
    """Stands in for the container: every site shows a login form."""
    writer = ResultWriter(root, job.job_id)
    for fqdn in job.targets:
        (root / fqdn).mkdir(parents=True, exist_ok=True)
        (root / fqdn / "shot.png").write_bytes(PNG_SIGNATURE + b"png")
        writer.write(
            CaptureResult(
                fqdn=fqdn,
                url=f"https://{fqdn}/",
                status=CaptureStatus.OK,
                captured_at=datetime.now(UTC),
                duration_ms=900,
                screenshot_path=Path(fqdn) / "shot.png",
                signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
            )
        )


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("LH_CONFIG", str(ROOT / "configs" / "default.yaml"))
    return Settings(
        db_path=tmp_path / "w.duckdb",
        ct=CTConfig(flush_max_rows=1),
        capture=CaptureConfig(output_dir=tmp_path / "captures"),
        alert=AlertConfig(file_path=tmp_path / "alerts.jsonl"),
        classify=ClassifyConfig(min_interval_s=0),
    )


_INDEX: list[VariantIndex] = []


def parts(settings: Settings) -> tuple[MatchStore, Scorer]:
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    if not _INDEX:  # 1s+ to build, and identical for every test here
        _INDEX.append(VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds))
    return store, Scorer(settings.brands, settings.scoring, _INDEX[0])


def notifications(settings: Settings) -> list[dict[str, Any]]:
    assert settings.alert.file_path is not None
    if not settings.alert.file_path.exists():
        return []
    lines = settings.alert.file_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


async def test_a_certificate_becomes_a_notification_without_anyone_running_a_command(
    settings: Settings,
) -> None:
    store, scorer = parts(settings)
    assert settings.alert.file_path is not None
    sinks = [FileSink(settings.alert.file_path)]

    completed = await watch(
        settings,
        store,
        scorer,
        StreamThenWait(),
        phishing_kit_everywhere,
        StubClassifier(),
        None,
        sinks,
        interval_s=0.05,
        cycles=2,
    )

    assert completed == 2
    announced = {n["fqdn"] for n in notifications(settings)}
    assert "paypa1-secure-login.com" in announced  # from the CT fixture, end to end
    assert all(n["label"] == "phishing" for n in notifications(settings))


async def test_a_second_cycle_does_not_announce_the_same_site_again(settings: Settings) -> None:
    store, scorer = parts(settings)
    assert settings.alert.file_path is not None
    sinks = [FileSink(settings.alert.file_path)]

    await watch(
        settings,
        store,
        scorer,
        StreamThenWait(),
        phishing_kit_everywhere,
        StubClassifier(),
        None,
        sinks,
        interval_s=0.05,
        cycles=4,
    )

    fqdns = [n["fqdn"] for n in notifications(settings)]
    assert fqdns and len(fqdns) == len(set(fqdns))


async def test_a_failing_capture_stage_is_counted_and_the_rest_still_runs(
    settings: Settings,
) -> None:
    store, scorer = parts(settings)
    # Alerts waiting for a capture, and nothing captured yet.
    await run_pipeline(StreamThenWait(end=True), scorer, store, 60, 1)
    assert settings.alert.file_path is not None
    sinks = [FileSink(settings.alert.file_path)]

    async def broken_container(job: CaptureJob, root: Path) -> None:
        raise OSError("docker exploded")

    stats = await run_cycle(settings, store, broken_container, StubClassifier(), None, sinks)

    assert stats.failed_stages == 1  # the capture stage, reported
    assert stats.captured == 0 and stats.notified == 0  # later stages ran, found nothing


async def test_a_stage_that_raises_does_not_end_the_watch(settings: Settings) -> None:
    store, scorer = parts(settings)

    class ExplodingClassifier(StubClassifier):
        async def classify(self, item: Any) -> Any:
            raise RuntimeError("model API went away")

    completed = await watch(
        settings,
        store,
        scorer,
        StreamThenWait(),
        phishing_kit_everywhere,
        ExplodingClassifier(),
        None,
        [],
        interval_s=0.05,
        cycles=3,
    )

    assert completed == 3


async def test_buffered_matches_are_flushed_when_the_watch_stops(settings: Settings) -> None:
    store, scorer = parts(settings)
    settings.ct.flush_max_rows = 10_000  # nothing flushes on its own during the run

    await watch(
        settings,
        store,
        scorer,
        StreamThenWait(),
        phishing_kit_everywhere,
        StubClassifier(),
        None,
        [],
        interval_s=0.05,
        cycles=2,
    )

    assert store.pending_captures(100, 24)  # the matches reached the database


async def test_a_stream_that_ends_stops_the_watch_loudly(settings: Settings) -> None:
    """A silent watch with no input would look healthy while seeing nothing."""
    store, scorer = parts(settings)

    with pytest.raises(IngestionStoppedError, match="ended"):
        await watch(
            settings,
            store,
            scorer,
            StreamThenWait(end=True),
            phishing_kit_everywhere,
            StubClassifier(),
            None,
            [],
            interval_s=0.05,
            cycles=5,
        )
