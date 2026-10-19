"""The evaluation reads local feed files next to the tracked dataset, once per site."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lookalike_hunter.eval.dataset import DatasetError, load_all_datasets


def _line(fqdn: str, source: str) -> str:
    return json.dumps(
        {
            "brand": "microsoft",
            "expected": "phishing",
            "fqdn": fqdn,
            "label_basis": "feed",
            "labelled_at": "2026-09-26",
            "labelled_by": "agent",
            "note": "test fixture",
            "source": source,
            "suggestion": "phishing",
        }
    )


def test_tracked_and_feed_sites_are_both_loaded(tmp_path: Path) -> None:
    main = tmp_path / "eval.jsonl"
    main.write_text(_line("tracked.example", "alerts") + "\n", encoding="utf-8")
    feed = tmp_path / "feed"
    feed.mkdir()
    (feed / "openphish.jsonl").write_text(
        _line("feed.example", "openphish") + "\n", encoding="utf-8"
    )

    fqdns = {site.fqdn for site in load_all_datasets(main, feed)}

    assert fqdns == {"tracked.example", "feed.example"}


def test_missing_feed_folder_is_not_an_error(tmp_path: Path) -> None:
    main = tmp_path / "eval.jsonl"
    main.write_text(_line("tracked.example", "alerts") + "\n", encoding="utf-8")

    sites = load_all_datasets(main, tmp_path / "no-such-folder")

    assert [site.fqdn for site in sites] == ["tracked.example"]


def test_site_in_two_files_is_refused(tmp_path: Path) -> None:
    main = tmp_path / "eval.jsonl"
    main.write_text(_line("same.example", "alerts") + "\n", encoding="utf-8")
    feed = tmp_path / "feed"
    feed.mkdir()
    (feed / "openphish.jsonl").write_text(
        _line("same.example", "openphish") + "\n", encoding="utf-8"
    )

    with pytest.raises(DatasetError, match=r"same\.example"):
        load_all_datasets(main, feed)
