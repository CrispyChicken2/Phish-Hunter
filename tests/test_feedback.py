"""Analyst labels: written into the benchmark without damaging anything else in it."""

import json
from datetime import date
from pathlib import Path

import pytest

from lookalike_hunter.classify.schema import Label
from lookalike_hunter.eval.dataset import load_all_datasets, load_dataset
from lookalike_hunter.eval.feedback import (
    FEED_LABELS_FILE,
    HUMAN,
    all_current_labels,
    current_labels,
    label_destination,
    record_label,
)

TODAY = date(2026, 10, 3)

EXISTING = (
    "# Candidate sites for evaluation.\n"
    '{"brand": "apple", "expected": "legitimate", "fqdn": "a.test", "label_basis": '
    '"screenshot", "labelled_at": "2026-09-26", "labelled_by": "agent", "note": null, '
    '"source": "alerts", "suggestion": null}\n'
    '{"brand": "paypal", "expected": "phishing", "fqdn": "b.test", "label_basis": "feed", '
    '"labelled_at": "2026-09-26", "labelled_by": "agent", "note": "gone", '
    '"source": "openphish", "suggestion": null}\n'
)


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    path = tmp_path / "eval.jsonl"
    path.write_text(EXISTING, encoding="utf-8")
    return path


def entries(path: Path) -> dict[str, dict[str, object]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return {
        json.loads(line)["fqdn"]: json.loads(line)
        for line in lines
        if line.strip() and not line.startswith("#")
    }


def test_a_new_site_is_appended_as_a_human_label(dataset: Path) -> None:
    previous = record_label(
        dataset, "New.Test", Label.PARKED, brand="paypal", suggestion="phishing", today=TODAY
    )

    assert previous is None
    entry = entries(dataset)["new.test"]
    assert entry["expected"] == "parked"
    assert entry["labelled_by"] == HUMAN
    assert entry["suggestion"] == "phishing"  # what the model said, for later analysis
    assert entry["labelled_at"] == "2026-10-03"


def test_relabelling_replaces_the_line_and_leaves_every_other_line_alone(dataset: Path) -> None:
    before = dataset.read_text(encoding="utf-8").splitlines()

    previous = record_label(dataset, "a.test", Label.PHISHING, today=TODAY)

    after = dataset.read_text(encoding="utf-8").splitlines()
    assert previous is not None and previous.expected == "legitimate"
    assert len(after) == len(before)
    assert after[0] == before[0] and after[2] == before[2]  # byte for byte
    assert entries(dataset)["a.test"]["expected"] == "phishing"


def test_the_label_it_replaces_is_kept_in_the_note(dataset: Path) -> None:
    """The agent's label is evidence too, not something to overwrite silently."""
    record_label(dataset, "b.test", Label.LEGITIMATE, today=TODAY)

    entry = entries(dataset)["b.test"]
    assert entry["note"] == "gone; relabelled by a human; was phishing (agent)"
    assert entry["source"] == "openphish"  # provenance is untouched
    assert entry["label_basis"] == "screenshot"


def test_a_human_changing_their_own_mind_adds_no_noise(dataset: Path) -> None:
    record_label(dataset, "new.test", Label.PARKED, today=TODAY)
    record_label(dataset, "new.test", Label.PHISHING, today=TODAY)

    entry = entries(dataset)["new.test"]
    assert entry["expected"] == "phishing" and entry["note"] is None
    assert list(entries(dataset)).count("new.test") == 1


def test_the_result_is_still_a_valid_benchmark(dataset: Path) -> None:
    record_label(dataset, "a.test", Label.PHISHING, today=TODAY)
    record_label(dataset, "c.test", Label.UNKNOWN, today=TODAY)

    sites = {site.fqdn: site.expected for site in load_dataset(dataset)}

    assert sites == {"a.test": Label.PHISHING, "b.test": Label.PHISHING, "c.test": Label.UNKNOWN}


def test_unreachable_is_not_a_label(dataset: Path) -> None:
    """It describes our visit, not the site."""
    with pytest.raises(ValueError, match="visit"):
        record_label(dataset, "a.test", Label.UNREACHABLE)


@pytest.mark.parametrize("hostile", ['evil.test", "expected": "x', "a b.test", "x\n{}"])
def test_a_hostile_hostname_never_reaches_the_file(dataset: Path, hostile: str) -> None:
    with pytest.raises(ValueError, match="hostname"):
        record_label(dataset, hostile, Label.PHISHING)
    assert dataset.read_text(encoding="utf-8") == EXISTING


def test_a_missing_dataset_is_created_with_its_header(tmp_path: Path) -> None:
    path = tmp_path / "new" / "eval.jsonl"

    record_label(path, "a.test", Label.PARKED, today=TODAY)

    assert path.read_text(encoding="utf-8").startswith("# Candidate sites")
    assert [s.fqdn for s in load_dataset(path)] == ["a.test"]


def test_no_temporary_file_is_left_behind(dataset: Path) -> None:
    record_label(dataset, "a.test", Label.PARKED, today=TODAY)

    assert [p.name for p in dataset.parent.iterdir()] == ["eval.jsonl"]


def test_current_labels_reports_who_labelled_what(dataset: Path) -> None:
    record_label(dataset, "a.test", Label.PARKED, today=TODAY)

    labels = current_labels(dataset)

    assert labels["a.test"].labelled_by == HUMAN and labels["a.test"].expected == "parked"
    assert labels["b.test"].labelled_by == "agent"


def test_windows_line_endings_are_kept(tmp_path: Path) -> None:
    """A Windows checkout has CRLF; rewriting it as LF would touch every line."""
    path = tmp_path / "eval.jsonl"
    path.write_bytes(EXISTING.replace("\n", "\r\n").encode("utf-8"))
    before = path.read_bytes().split(b"\r\n")

    record_label(path, "a.test", Label.PHISHING, today=TODAY)

    after = path.read_bytes().split(b"\r\n")
    assert b"\n" not in path.read_bytes().replace(b"\r\n", b"")
    assert after[0] == before[0] and after[2] == before[2]


# ------------------------------------------------- which file a label belongs in


def test_a_site_our_scoring_found_goes_to_the_tracked_dataset(dataset: Path) -> None:
    assert label_destination(dataset, "paypa1-login.test", found_by_scoring=True) == (
        dataset,
        "alerts",
    )


def test_a_site_from_the_feed_stays_out_of_git(dataset: Path) -> None:
    """The feed's terms forbid publishing its sites; datasets/feed/ is ignored by git."""
    path, source = label_destination(dataset, "outlook-ashy.vercel.app", found_by_scoring=False)
    record_label(path, "outlook-ashy.vercel.app", Label.PHISHING, today=TODAY, source=source)

    assert path == dataset.parent / "feed" / FEED_LABELS_FILE
    assert entries(path)["outlook-ashy.vercel.app"]["source"] == "openphish"
    assert "outlook-ashy.vercel.app" not in entries(dataset)
    assert len(load_all_datasets(dataset)) == 3  # the evaluation still reads it


def test_a_site_already_labelled_is_relabelled_where_it_is(dataset: Path) -> None:
    older = dataset.parent / "feed" / "openphish-eval.jsonl"
    older.parent.mkdir()
    older.write_text(
        '{"expected": "phishing", "fqdn": "old-feed.test", "labelled_at": "2026-09-26", '
        '"source": "openphish"}\n',
        encoding="utf-8",
    )

    assert label_destination(dataset, "b.test", found_by_scoring=False) == (dataset, "alerts")
    assert label_destination(dataset, "old-feed.test", found_by_scoring=True)[0] == older


def test_labels_from_both_files_are_shown(dataset: Path) -> None:
    path, source = label_destination(dataset, "f.test", found_by_scoring=False)
    record_label(path, "f.test", Label.PARKED, today=TODAY, source=source)

    assert set(all_current_labels(dataset)) == {"a.test", "b.test", "f.test"}
