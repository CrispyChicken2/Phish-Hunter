"""Dataset builder tests. No network: the feed is a recorded sample."""

from datetime import date
from pathlib import Path

import pytest

from lookalike_hunter.config import BrandConfig, load_settings
from lookalike_hunter.eval.build import (
    Candidate,
    candidates_from_feed,
    hard_negative_candidates,
    write_candidates,
)
from lookalike_hunter.eval.dataset import UnlabelledSiteError, iter_dataset, load_dataset
from lookalike_hunter.eval.feeds import brand_for_url, filter_to_brands, parse_url_feed

ROOT = Path(__file__).parents[1]
FEED = ROOT / "tests" / "fixtures" / "openphish_sample.txt"
TODAY = date(2026, 9, 27)


@pytest.fixture(scope="module")
def brands() -> list[BrandConfig]:
    return load_settings(ROOT / "configs" / "default.yaml").brands


# ------------------------------------------------------------------------- parsing


def test_feed_parsing_keeps_only_usable_http_urls() -> None:
    entries = parse_url_feed(FEED.read_text(encoding="utf-8"), source="openphish")

    hosts = [e.fqdn for e in entries]
    assert "paypal-account-verify.example-phish.com" in hosts
    assert "192.0.2.44" in hosts  # a bare IP is a real feed shape
    assert "not-a-url-at-all" not in hosts
    assert not any("ftp" in e.url for e in entries)  # non-http schemes dropped
    assert len(hosts) == len(set(hosts))  # the duplicate host appears once


def test_comments_are_ignored() -> None:
    entries = parse_url_feed("# a comment\nhttps://a.example-phish.com/x\n", source="s")
    assert [e.fqdn for e in entries] == ["a.example-phish.com"]


# ---------------------------------------------------------------- brand selection


def test_brand_is_found_anywhere_in_the_url(brands: list[BrandConfig]) -> None:
    """The brand may appear only in the path, where the Scorer cannot see it."""
    assert brand_for_url("http://secure-login.example.net/paypal/verify", brands) == "paypal"
    assert brand_for_url("https://appleid-locked.example.org/unlock", brands) == "apple"
    assert brand_for_url("https://unrelated-crypto.example.com/claim", brands) is None


def test_selection_does_not_use_the_scorer(brands: list[BrandConfig]) -> None:
    """Selecting with our own detector would make recall 100% by construction.

    This entry mentions the brand only in the path, so the Scorer scores the
    hostname at zero, yet it must still enter the dataset as a site we ought to
    have caught.
    """
    from lookalike_hunter.scoring.scorer import Scorer
    from lookalike_hunter.variants.generator import VariantIndex

    settings = load_settings(ROOT / "configs" / "default.yaml")
    scorer = Scorer(settings.brands, settings.scoring, VariantIndex([]))
    url = "http://secure-login-portal.example-phish.net/paypal/verify"

    assert scorer.score("secure-login-portal.example-phish.net") == []
    assert brand_for_url(url, brands) == "paypal"


def test_filter_records_the_matched_brand(brands: list[BrandConfig]) -> None:
    entries = filter_to_brands(
        parse_url_feed(FEED.read_text(encoding="utf-8"), "openphish"), brands
    )

    by_host = {e.fqdn: e.brand for e in entries}
    assert by_host["paypal-account-verify.example-phish.com"] == "paypal"
    assert by_host["secure-login-portal.example-phish.net"] == "paypal"  # brand in the path
    assert by_host["192.0.2.44"] == "microsoft"  # brand in the path of a bare IP
    assert "unrelated-crypto-drainer.example-phish.com" not in by_host


# -------------------------------------------------------------------- candidates


def test_feed_candidates_are_unlabelled_with_provenance(
    brands: list[BrandConfig],
) -> None:
    candidates = candidates_from_feed(FEED.read_text(encoding="utf-8"), brands, source="openphish")

    assert candidates
    for candidate in candidates:
        assert candidate.source == "openphish"
        assert candidate.suggestion == "phishing"  # a suggestion, not a label
        assert "confirm" in (candidate.note or "")


def test_hard_negatives_are_seeded() -> None:
    hosts = {c.fqdn for c in hard_negative_candidates()}

    assert "hummelcloud.net" in hosts  # the icloud regression
    assert "microsoft-falcon.net" in hosts  # brand infrastructure
    assert all(c.suggestion == "legitimate" for c in hard_negative_candidates())


# ------------------------------------------------------------------------ writing


def test_written_candidates_have_no_label_and_are_refused_by_evaluation(
    tmp_path: Path,
) -> None:
    out = tmp_path / "dataset.jsonl"

    added, skipped = write_candidates(out, hard_negative_candidates(), today=TODAY)

    assert added > 0 and skipped == 0
    assert "docs/labelling-protocol.md" in out.read_text(encoding="utf-8")

    # An unreviewed file cannot quietly become a benchmark.
    with pytest.raises(UnlabelledSiteError, match="has no label yet"):
        load_dataset(out)

    # Review tooling can still read them.
    assert len(list(iter_dataset(out, allow_unlabelled=True))) == added


def test_rebuilding_never_discards_existing_labels(tmp_path: Path) -> None:
    out = tmp_path / "dataset.jsonl"
    out.write_text(
        '{"fqdn": "hummelcloud.net", "expected": "legitimate", "source": "me", '
        '"labelled_at": "2026-09-27"}\n',
        encoding="utf-8",
    )

    _added, skipped = write_candidates(out, hard_negative_candidates(), today=TODAY)

    assert skipped == 1  # the already-labelled site was left alone
    lines = [line for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert '"expected": "legitimate"' in lines[0]  # untouched


def test_duplicate_candidates_are_added_once(tmp_path: Path) -> None:
    out = tmp_path / "dataset.jsonl"
    twice = [Candidate("a.com", "s"), Candidate("a.com", "s")]

    added, skipped = write_candidates(out, twice, today=TODAY)

    assert (added, skipped) == (1, 1)
