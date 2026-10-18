"""Archiving captures: a local copy is deleted only after its upload succeeded (P1.6)."""

import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lookalike_hunter.archive import JOBS_DIR, archive_captures, s3_uploader

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
OLD = (NOW - timedelta(hours=10)).timestamp()
YOUNG = (NOW - timedelta(minutes=5)).timestamp()


def make(path: Path, mtime: float, text: str = "capture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


class Recorder:
    """A fake uploader: remembers each key and can be told to fail."""

    def __init__(self, fail: bool = False) -> None:
        self.keys: list[str] = []
        self.fail = fail

    def __call__(self, path: Path, key: str) -> None:
        if self.fail:
            raise RuntimeError("network down")
        self.keys.append(key)


def run(root: Path, upload: Recorder) -> None:
    archive_captures(root, "captures", timedelta(hours=6), upload, NOW)


def test_an_old_capture_is_uploaded_under_its_relative_key_and_then_deleted(
    tmp_path: Path,
) -> None:
    old = make(tmp_path / "site.example" / "shot.png", OLD)
    upload = Recorder()

    run(tmp_path, upload)

    assert upload.keys == ["captures/site.example/shot.png"]
    assert not old.exists()


def test_a_young_capture_is_left_alone(tmp_path: Path) -> None:
    young = make(tmp_path / "fresh.png", YOUNG)
    upload = Recorder()

    run(tmp_path, upload)

    assert upload.keys == []
    assert young.exists()


def test_a_failed_upload_keeps_the_local_copy(tmp_path: Path) -> None:
    old = make(tmp_path / "shot.png", OLD)
    stats_upload = Recorder(fail=True)

    stats = archive_captures(tmp_path, "captures", timedelta(hours=6), stats_upload, NOW)

    assert stats.failed == 1 and stats.archived == 0
    assert old.exists()  # never delete what was not stored


def test_the_job_folder_is_never_touched(tmp_path: Path) -> None:
    job = make(tmp_path / JOBS_DIR / "job-1.json", OLD)
    upload = Recorder()

    run(tmp_path, upload)

    assert upload.keys == []
    assert job.exists()


def test_symbolic_links_are_neither_followed_nor_uploaded(tmp_path: Path) -> None:
    secret = make(tmp_path / "outside" / "secret.txt", OLD)
    link = tmp_path / "captures" / "link.txt"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("creating symbolic links needs a privilege on this machine")
    upload = Recorder()

    run(tmp_path / "captures", upload)

    assert upload.keys == []
    assert secret.exists()


def test_the_uploader_runs_the_cli_with_an_argument_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert kwargs.get("shell") is None  # never a shell: names come from the container
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    local = make(tmp_path / "shot.png", OLD)

    s3_uploader("bucket-x")(local, "captures/shot.png")

    assert calls == [
        ["aws", "s3", "cp", "--only-show-errors", str(local), "s3://bucket-x/captures/shot.png"]
    ]
