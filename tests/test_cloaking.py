"""Cloaking comparison: the same sites, captured from two Vantage points."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.cli import main
from lookalike_hunter.eval.cloaking import SideCapture, SitePair, compare, load_side
from lookalike_hunter.ingest.store import MatchStore

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
LOGIN = PageSignals(title="Sign in", form_count=1, has_password_input=True)


def side(fqdn: str = "evil.test", hours: float = 0, **fields: Any) -> SideCapture:
    values: dict[str, Any] = {"status": "ok", "http_status": 200, "final_host": fqdn}
    values.update(fields)
    return SideCapture(fqdn, NOW + timedelta(hours=hours), **values)


def pair(first: SideCapture, second: SideCapture) -> SitePair:
    return SitePair(first.fqdn, first, second)


# ------------------------------------------------------------------------ pairing


def test_each_site_is_compared_on_its_two_closest_captures() -> None:
    first = {"evil.test": [side(hours=0, title="old"), side(hours=10, title="close")]}
    second = {"evil.test": [side(hours=11, title="close")]}

    report = compare(first, second, "aws", "home")

    assert [p.first.title for p in report.pairs] == ["close"]
    assert report.differing == []


def test_captures_too_far_apart_in_time_are_not_compared() -> None:
    """A site taken down in between would otherwise look cloaked."""
    first = {"evil.test": [side(hours=0)]}
    second = {"evil.test": [side(hours=7, status="dns_error")]}

    report = compare(first, second, "aws", "home", max_gap=timedelta(hours=6))

    assert report.pairs == [] and report.too_far_apart == 1


def test_sites_seen_from_one_side_only_are_counted_not_compared() -> None:
    report = compare(
        {"a.test": [side("a.test")], "both.test": [side("both.test")]},
        {"both.test": [side("both.test")], "b.test": [side("b.test")], "c.test": [side("c.test")]},
        "aws",
        "home",
    )

    assert [p.fqdn for p in report.pairs] == ["both.test"]
    assert (report.only_first, report.only_second) == (1, 2)


# -------------------------------------------------------------------- differences


def test_a_site_that_answers_only_one_side_is_reported() -> None:
    found = pair(side(status="timeout", http_status=None), side())

    assert found.unreachable_on_one_side and found.differs
    assert found.content_differences == ()  # nothing to compare against an error


@pytest.mark.parametrize(
    ("change", "difference"),
    [
        ({"http_status": 404}, "http status"),
        ({"final_host": "www.google.com"}, "final site"),
        ({"has_login_form": False}, "login form"),
        ({"title": "Welcome to nginx!"}, "title"),
    ],
)
def test_each_kind_of_content_difference_is_named(change: dict[str, Any], difference: str) -> None:
    home = side(title="Sign in", has_login_form=True)
    aws = side(**{"title": "Sign in", "has_login_form": True, **change})

    assert pair(aws, home).content_differences == (difference,)


def test_titles_differing_only_in_case_or_spacing_are_the_same_page() -> None:
    assert pair(side(title="Sign  In "), side(title="sign in")).content_differences == ()


def test_verdicts_are_compared_only_when_both_sides_were_judged() -> None:
    assert pair(side(verdict="parked"), side(verdict="phishing")).different_verdict
    assert not pair(side(verdict=None), side(verdict="phishing")).different_verdict
    assert not pair(side(verdict="phishing"), side(verdict="phishing")).different_verdict


def test_the_report_counts_each_kind_once_per_site() -> None:
    report = compare(
        {
            "gone.test": [side("gone.test", status="timeout")],
            "cloaked.test": [side("cloaked.test", final_host="www.google.com", verdict="legit")],
            "same.test": [side("same.test")],
        },
        {
            "gone.test": [side("gone.test")],
            "cloaked.test": [side("cloaked.test", verdict="phishing")],
            "same.test": [side("same.test")],
        },
        "aws",
        "home",
    )

    assert report.unreachable_on_one_side == 1
    assert report.different_content == 1
    assert report.different_verdict == 1
    assert [p.fqdn for p in report.differing] == ["cloaked.test", "gone.test"]


# ----------------------------------------------------------------------- database


def store_capture(
    store: MatchStore,
    vantage: str | None,
    status: CaptureStatus = CaptureStatus.OK,
    signals: PageSignals | None = LOGIN,
    final_url: str | None = "https://Evil.test/login",
) -> None:
    store.save_capture(
        CaptureResult(
            fqdn="evil.test",
            url="https://evil.test/",
            status=status,
            captured_at=NOW,
            duration_ms=900,
            final_url=final_url if status is CaptureStatus.OK else None,
            http_status=200 if status is CaptureStatus.OK else None,
            signals=signals if status is CaptureStatus.OK else None,
        ),
        vantage=vantage,
    )


def judge(store: MatchStore, label: Label | None, backend: str) -> None:
    verdict = Verdict(label=label, confidence=0.9, evidence="x") if label else None
    store.save_verdict(1, "evil.test", backend, "m", verdict, NOW)


def test_a_side_is_read_from_the_captures_of_its_vantage_point_only(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    store_capture(store, "aws")
    store_capture(store, "home", CaptureStatus.TIMEOUT)
    store_capture(store, None)  # made before vantage points were recorded

    loaded = load_side(store.db_path, "aws", backend=None)

    assert loaded == {
        "evil.test": [SideCapture("evil.test", NOW, "ok", 200, "evil.test", "Sign in", True, None)]
    }


def test_a_side_keeps_the_latest_verdict_of_the_chosen_backend(tmp_path: Path) -> None:
    """The offline stub and a real model disagree for reasons unrelated to cloaking."""
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    store_capture(store, "aws")
    judge(store, Label.PHISHING, backend="mistral")
    judge(store, Label.PARKED, backend="stub")
    judge(store, None, backend="mistral-retry")  # an error row: no verdict at all

    assert load_side(store.db_path, "aws", "mistral")["evil.test"][0].verdict == "phishing"
    assert load_side(store.db_path, "aws", "stub")["evil.test"][0].verdict == "parked"
    assert load_side(store.db_path, "aws", "mistral-retry")["evil.test"][0].verdict is None


def test_the_command_compares_two_databases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    aws = MatchStore(tmp_path / "aws.duckdb", 0.7)
    home = MatchStore(tmp_path / "home.duckdb", 0.7)
    store_capture(aws, "aws-eu-north-1", signals=PageSignals(title="Index of /\x1b[2J"))
    store_capture(home, "home")
    monkeypatch.setenv("LH_DB_PATH", str(aws.db_path))
    monkeypatch.setenv("LH_CAPTURE__VANTAGE", "aws-eu-north-1")

    main(
        [
            "--config", str(ROOT / "configs" / "default.yaml"),
            "cloaking", "--against", "home", "--against-db", str(home.db_path),
        ]
    )  # fmt: skip

    out = capsys.readouterr().out
    assert "1 site(s) captured from both aws-eu-north-1 and home" in out
    assert "different content:       1" in out
    assert "evil.test  differs: login form, title" in out
    assert "\x1b" not in out  # page titles are hostile text


def test_the_command_refuses_to_compare_a_side_with_itself(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="same captures"):
        main(
            [
                "--config", str(ROOT / "configs" / "default.yaml"),
                "cloaking", "--vantage", "home", "--against", "home",
                "--db", str(tmp_path / "t.duckdb"),
            ]
        )  # fmt: skip
