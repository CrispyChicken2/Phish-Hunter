from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.base import ClassificationError, ClassificationInput, StubClassifier
from lookalike_hunter.classify.runner import run_classifications
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.ingest.store import MatchStore

NOW = datetime(2026, 9, 21, 10, 0, tzinfo=UTC)
FAKE_PNG = bytes.fromhex("89504e470d0a1a0a") + b"fake"


def store_with_capture(
    tmp_path: Path,
    status: CaptureStatus = CaptureStatus.OK,
    with_screenshot: bool = True,
    signals: PageSignals | None = None,
) -> MatchStore:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    shot: Path | None = None
    if with_screenshot:
        shot = tmp_path / "shot.png"
        shot.write_bytes(FAKE_PNG)
    store.save_capture(
        CaptureResult(
            fqdn="appleid-security.com",
            url="https://appleid-security.com/",
            status=status,
            captured_at=NOW,
            duration_ms=900,
            final_url="https://appleid-security.com/login",
            screenshot_path=Path("shot.png") if shot else None,
            signals=signals or PageSignals(title="Sign in", form_count=1, has_password_input=True),
        )
    )
    return store


def verdict_rows(store: MatchStore) -> list[tuple[str, str, float, str | None]]:
    with duckdb.connect(str(store.db_path), read_only=True) as con:
        return con.execute(
            "SELECT fqdn, label, confidence, error FROM verdicts ORDER BY verdict_id"
        ).fetchall()


async def test_stub_classifies_and_persists(tmp_path: Path) -> None:
    store = store_with_capture(tmp_path)

    stats = await run_classifications(
        store, StubClassifier(), None, limit=10, max_retries=2, captures_dir=tmp_path
    )

    assert stats.attempted == 1 and stats.failed == 0
    rows = verdict_rows(store)
    assert rows[0][1] == "phishing"


async def test_already_classified_captures_are_skipped(tmp_path: Path) -> None:
    store = store_with_capture(tmp_path)
    await run_classifications(store, StubClassifier(), None, 10, 2, captures_dir=tmp_path)

    second = await run_classifications(store, StubClassifier(), None, 10, 2, captures_dir=tmp_path)

    assert second.attempted == 0
    assert len(verdict_rows(store)) == 1


async def test_unreachable_capture_is_labelled_without_calling_the_model(tmp_path: Path) -> None:
    store = store_with_capture(tmp_path, status=CaptureStatus.DNS_ERROR)

    class Exploding:
        name = "stub"

        async def classify(self, item: ClassificationInput) -> Verdict:
            raise AssertionError("the model must not be called for an unreachable site")

    stats = await run_classifications(store, Exploding(), None, 10, 2, captures_dir=tmp_path)

    assert stats.by_label[str(Label.UNREACHABLE)] == 1
    assert verdict_rows(store)[0][1] == "unreachable"


async def test_relative_screenshot_path_is_resolved_against_captures_dir(tmp_path: Path) -> None:
    """A capture written inside the container is read back on the host."""
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    captures = tmp_path / "captures"
    (captures / "site.com").mkdir(parents=True)
    (captures / "site.com" / "shot.png").write_bytes(FAKE_PNG)
    store.save_capture(
        CaptureResult(
            fqdn="site.com",
            url="https://site.com/",
            status=CaptureStatus.OK,
            captured_at=NOW,
            duration_ms=10,
            screenshot_path=Path("site.com/shot.png"),
            signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
        )
    )

    await run_classifications(store, StubClassifier(), None, 10, 2, captures_dir=captures)

    assert verdict_rows(store)[0][1] == "phishing"  # not "unknown": the file was found


@pytest.mark.parametrize("stored", ["../secret.txt", "SECRET_ABSOLUTE"])
async def test_a_stored_path_outside_the_captures_dir_is_never_read(
    tmp_path: Path, stored: str
) -> None:
    """The DB is written by the capture container; a compromised one must not make
    the host upload an arbitrary file to the model API."""
    secret = tmp_path / "secret.txt"
    secret.write_bytes(FAKE_PNG)
    captures = tmp_path / "captures"
    captures.mkdir()
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    store.save_capture(
        CaptureResult(
            fqdn="site.com",
            url="https://site.com/",
            status=CaptureStatus.OK,
            captured_at=NOW,
            duration_ms=10,
            screenshot_path=secret if stored == "SECRET_ABSOLUTE" else Path(stored),
            signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
        )
    )
    read: list[Path] = []

    class Recording(StubClassifier):
        async def classify(self, item: ClassificationInput) -> Verdict:
            read.append(item.screenshot_path)
            return await super().classify(item)

    await run_classifications(store, Recording(), None, 10, 2, captures_dir=captures)

    assert read == []
    assert verdict_rows(store)[0][1] == "unknown"


async def test_missing_screenshot_is_unknown(tmp_path: Path) -> None:
    store = store_with_capture(tmp_path, with_screenshot=False)
    await run_classifications(store, StubClassifier(), None, 10, 2, captures_dir=tmp_path)
    assert verdict_rows(store)[0][1] == "unknown"


async def test_backend_failure_is_recorded_not_raised(tmp_path: Path) -> None:
    store = store_with_capture(tmp_path)

    class AlwaysFails:
        name = "stub"

        async def classify(self, item: ClassificationInput) -> Verdict:
            raise ClassificationError("API returned 401", retryable=False)

    stats = await run_classifications(store, AlwaysFails(), "m", 10, 2, captures_dir=tmp_path)

    assert stats.failed == 1
    _fqdn, label, _confidence, error = verdict_rows(store)[0]
    assert label == "error"
    assert error is not None and "401" in error


async def test_nothing_pending_is_a_noop(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    stats = await run_classifications(store, StubClassifier(), None, 10, 2, captures_dir=tmp_path)
    assert stats.attempted == 0


@pytest.mark.parametrize("limit", [1, 5])
async def test_limit_is_respected(tmp_path: Path, limit: int) -> None:
    store = store_with_capture(tmp_path)
    for i in range(3):
        store.save_capture(
            CaptureResult(
                fqdn=f"host{i}.com",
                url=f"https://host{i}.com/",
                status=CaptureStatus.TIMEOUT,
                captured_at=NOW,
                duration_ms=10,
            )
        )

    stats = await run_classifications(
        store, StubClassifier(), None, limit, 2, captures_dir=tmp_path
    )
    assert stats.attempted == min(limit, 4)


async def test_a_skipped_write_is_reported_not_silent(tmp_path: Path) -> None:
    """A discarded verdict once made a model comparison report success with no data."""
    store = store_with_capture(tmp_path)
    verdict = Verdict(label=Label.PARKED, confidence=0.5, evidence="x")

    first = store.save_verdict(1, "a.com", "mistral", "m", verdict, NOW)
    second = store.save_verdict(1, "a.com", "mistral", "m", verdict, NOW)

    assert first is True
    assert second is False  # same capture, backend and model: skipped, and said so


async def test_the_same_capture_takes_one_verdict_per_model(tmp_path: Path) -> None:
    store = store_with_capture(tmp_path)
    verdict = Verdict(label=Label.PARKED, confidence=0.5, evidence="x")

    assert store.save_verdict(1, "a.com", "mistral", "small", verdict, NOW) is True
    assert store.save_verdict(1, "a.com", "mistral", "large", verdict, NOW) is True
