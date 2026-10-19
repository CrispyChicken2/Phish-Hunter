"""Which feed candidates the watch loop captures: fresh, newest first, once each."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from lookalike_hunter.capture.feed_entries import fresh_feed_targets
from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.eval.build import Candidate
from lookalike_hunter.ingest.store import MatchStore

TODAY = date(2026, 10, 20)


def write_candidates(path: Path, entries: list[tuple[str, date]]) -> None:
    """Append candidates in file order, as the feed timer does."""
    lines = [
        Candidate(
            fqdn=fqdn, source="openphish", suggestion="phishing", brand="paypal"
        ).to_json_line(listed)
        for fqdn, listed in entries
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_newest_candidates_go_first_within_the_limit(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "s.duckdb", 0.7)
    path = tmp_path / "candidates.jsonl"
    write_candidates(path, [("a.example", TODAY), ("b.example", TODAY), ("c.example", TODAY)])

    targets = fresh_feed_targets(store, path, limit=2, max_age_days=1, today=TODAY)

    assert [t.fqdn for t in targets] == ["c.example", "b.example"]


def test_candidates_older_than_the_limit_are_skipped(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "s.duckdb", 0.7)
    path = tmp_path / "candidates.jsonl"
    write_candidates(path, [("old.example", TODAY - timedelta(days=3)), ("new.example", TODAY)])

    targets = fresh_feed_targets(store, path, limit=5, max_age_days=1, today=TODAY)

    assert [t.fqdn for t in targets] == ["new.example"]


def test_a_captured_site_is_never_visited_again(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "s.duckdb", 0.7)
    store.save_capture(
        CaptureResult(
            fqdn="seen.example",
            url="https://seen.example/",
            status=CaptureStatus.DNS_ERROR,
            captured_at=datetime.now(UTC) - timedelta(days=2),
            duration_ms=100,
        )
    )
    path = tmp_path / "candidates.jsonl"
    write_candidates(path, [("seen.example", TODAY), ("fresh.example", TODAY)])

    targets = fresh_feed_targets(store, path, limit=5, max_age_days=1, today=TODAY)

    assert [t.fqdn for t in targets] == ["fresh.example"]


def test_no_candidates_file_yet_means_nothing_to_do(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "s.duckdb", 0.7)

    assert fresh_feed_targets(store, tmp_path / "missing.jsonl", 5, 1, TODAY) == []
