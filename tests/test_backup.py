"""The daily backup: a consistent export of the database, packed and uploaded (P1.7)."""

import tarfile
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from lookalike_hunter.backup import _export_database, backup

STAMP = datetime(2026, 10, 19, 3, 0, tzinfo=UTC)


def make_database(path: Path) -> None:
    con = duckdb.connect(str(path))
    con.execute("CREATE TABLE matches (fqdn VARCHAR, score DOUBLE)")
    con.execute("INSERT INTO matches VALUES ('paypa1.example', 0.9)")
    con.close()


def test_the_database_is_exported_packed_and_uploaded(tmp_path: Path) -> None:
    db = tmp_path / "lookalike.duckdb"
    make_database(db)
    seen: dict[str, list[str]] = {}

    def upload(path: Path, key: str) -> None:
        # The archive must exist while it is uploaded, and must hold the export.
        with tarfile.open(path) as tar:
            seen[key] = tar.getnames()

    keys = backup(db, tmp_path / "absent.jsonl", "backups", STAMP, upload)

    assert keys == ["backups/database-20261019T030000Z.tar.gz"]
    names = seen[keys[0]]
    assert any(name.startswith("export/") and name.endswith(".parquet") for name in names)
    assert any(name == "export/load.sql" for name in names)


def test_the_dataset_is_uploaded_when_present(tmp_path: Path) -> None:
    db = tmp_path / "lookalike.duckdb"
    make_database(db)
    dataset = tmp_path / "eval.jsonl"
    dataset.write_text('{"fqdn": "example.com"}\n', encoding="utf-8")
    uploaded: list[str] = []

    keys = backup(db, dataset, "backups", STAMP, lambda _p, key: uploaded.append(key))

    assert keys == uploaded
    assert "backups/eval-20261019T030000Z.jsonl" in keys


def test_a_failed_upload_is_raised_not_hidden(tmp_path: Path) -> None:
    db = tmp_path / "lookalike.duckdb"
    make_database(db)

    def refuse(_path: Path, _key: str) -> None:
        raise RuntimeError("network down")

    try:
        backup(db, tmp_path / "absent.jsonl", "backups", STAMP, refuse)
    except RuntimeError as exc:
        assert "network down" in str(exc)
    else:  # pragma: no cover - the failure must reach the caller
        raise AssertionError("a failed upload must fail the backup")
    assert db.exists()  # the source is never touched


def test_a_quote_in_the_export_path_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "lookalike.duckdb"
    make_database(db)
    with pytest.raises(ValueError, match="quote"):
        _export_database(db, tmp_path / "it's" / "export")
