"""Detection on known phishing: Feed entries against the Matches our scoring stored."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from lookalike_hunter.cli import main
from lookalike_hunter.eval.detection import (
    Outcome,
    Timing,
    feed_detection,
    shared_platform,
)
from lookalike_hunter.ingest.parse import Certificate
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.scoring.scorer import Match, MatchFeatures

ROOT = Path(__file__).parents[1]


def flagged(store: MatchStore, fqdn: str, registered: str, score: float, day: int) -> None:
    seen = datetime(2026, 10, day, 9, 0, tzinfo=UTC)
    certificate = Certificate(
        f"{fqdn:0<64}"[:64], seen, "Let's Encrypt", seen, seen, "log", (fqdn,)
    )
    store.write([(certificate, Match(fqdn, registered, "paypal", score, MatchFeatures()))])


def feed_file(tmp_path: Path, *entries: tuple[str, int]) -> Path:
    path = tmp_path / "feed-entries.jsonl"
    lines = [
        json.dumps(
            {
                "fqdn": fqdn,
                "expected": None,
                "source": "openphish",
                "labelled_at": f"2026-10-{day:02d}",
                "brand": "paypal",
            }
        )
        for fqdn, day in entries
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def store(tmp_path: Path) -> MatchStore:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    flagged(store, "first-ever.test", "first-ever.test", 0.9, day=10)  # monitoring starts
    return store


def outcomes(store: MatchStore, feed: Path) -> dict[str, Outcome]:
    return {site.fqdn: site.outcome for site in feed_detection(feed, store.db_path).sites}


def test_a_feed_site_we_alerted_on_counts_as_caught(tmp_path: Path, store: MatchStore) -> None:
    flagged(store, "login.paypa1-secure.com", "paypa1-secure.com", 0.9, day=12)

    report = feed_detection(feed_file(tmp_path, ("paypa1-secure.com", 14)), store.db_path)

    # Caught through its registered domain: the certificate named a subdomain of it.
    (site,) = report.sites
    assert site.outcome is Outcome.ALERTED
    assert site.timing is Timing.BEFORE and report.timing(Timing.BEFORE) == 1


def test_a_match_below_the_alert_threshold_is_not_a_catch(
    tmp_path: Path, store: MatchStore
) -> None:
    flagged(store, "paypal-help.com", "paypal-help.com", 0.4, day=12)

    feed = feed_file(tmp_path, ("paypal-help.com", 12), ("never-seen.com", 12))

    assert outcomes(store, feed) == {
        "paypal-help.com": Outcome.MATCHED,
        "never-seen.com": Outcome.NOT_SEEN,
    }


def test_a_shared_platform_site_is_out_of_reach_not_missed(
    tmp_path: Path, store: MatchStore
) -> None:
    """Another tenant's alert on the same platform is not a catch of this one."""
    flagged(store, "paypal-login.vercel.app", "vercel.app", 0.9, day=12)

    feed = feed_file(tmp_path, ("outlook-ashy.vercel.app", 12), ("paypal-login.vercel.app", 12))

    assert outcomes(store, feed) == {
        "outlook-ashy.vercel.app": Outcome.OUT_OF_REACH,
        "paypal-login.vercel.app": Outcome.ALERTED,  # named by its own certificate
    }


def test_sites_listed_before_monitoring_began_are_left_out(
    tmp_path: Path, store: MatchStore
) -> None:
    feed = feed_file(tmp_path, ("old.com", 9), ("new.com", 10))

    report = feed_detection(feed, store.db_path)

    assert [s.fqdn for s in report.sites] == ["new.com"]
    assert report.listed_before_monitoring == 1


def test_a_site_listed_twice_keeps_its_first_listing(tmp_path: Path, store: MatchStore) -> None:
    flagged(store, "twice.com", "twice.com", 0.9, day=12)

    report = feed_detection(
        feed_file(tmp_path, ("twice.com", 13), ("twice.com", 11)), store.db_path
    )

    (site,) = report.sites
    assert site.listed_on == date(2026, 10, 11) and site.timing is Timing.AFTER


def test_shared_platforms_are_recognised_by_the_public_suffix_list() -> None:
    assert shared_platform("outlook-ashy.vercel.app")
    assert shared_platform("someone.github.io")
    assert not shared_platform("paypa1-secure.com")
    assert not shared_platform("login.paypa1-secure.co.uk")


def test_the_command_prints_shares_of_the_sites_within_reach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "cli.duckdb"
    store = MatchStore(db, 0.7)
    flagged(store, "paypa1-secure.com", "paypa1-secure.com", 0.9, day=10)
    feed = feed_file(
        tmp_path,
        ("paypa1-secure.com", 10),
        ("never-seen.com", 10),
        ("x.vercel.app", 10),
    )
    monkeypatch.setenv("LH_DB_PATH", str(db))

    main(
        [
            "--config", str(ROOT / "configs" / "default.yaml"),
            "detection", "--feed-entries", str(feed), "--list",
        ]
    )  # fmt: skip

    out = capsys.readouterr().out
    assert "3 Feed entries listed since monitoring began (2026-10-10)" in out
    assert "within reach of certificate monitoring:                   2" in out
    assert "alerted        1  (50.0% of those within reach)" in out
    assert "on the listing day           1" in out
