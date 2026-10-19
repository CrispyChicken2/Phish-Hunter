"""Feed-derived candidates must not be written under datasets/, which git tracks."""

from __future__ import annotations

from pathlib import Path

import pytest

from lookalike_hunter.cli import refuse_feed_output_in_datasets


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run from a fake repository root so the relative 'datasets' folder exists."""
    (tmp_path / "datasets" / "feed").mkdir(parents=True)
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_the_tracked_dataset_is_refused(repo: Path) -> None:
    with pytest.raises(SystemExit, match="refusing"):
        refuse_feed_output_in_datasets(Path("datasets/eval.jsonl"))


def test_the_labelled_feed_folder_is_refused_for_candidates(repo: Path) -> None:
    # Candidates are unlabelled; a file here would break the evaluation's loader.
    with pytest.raises(SystemExit, match="refusing"):
        refuse_feed_output_in_datasets(Path("datasets/feed/candidates.jsonl"))


def test_the_git_ignored_data_folder_is_allowed(repo: Path) -> None:
    refuse_feed_output_in_datasets(Path("data/feed-candidates.jsonl"))
