"""Daily backup of the database and the labelled dataset (P1.7).

The database is open for writing by `watch` at all times, so it is never copied
directly: a file copied while it changes can be inconsistent. Instead it is exported
through a read-only connection, which sees one consistent snapshot. The export is then
packed and uploaded. A failed upload fails the run; nothing is deleted.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from lookalike_hunter.archive import Uploader
from lookalike_hunter.ingest.store import connect_with_retry
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


def backup(
    db_path: Path,
    dataset_path: Path,
    prefix: str,
    stamp: datetime,
    upload: Uploader,
    staging: Path | None = None,
) -> list[str]:
    """Upload a snapshot of the database and, if present, the dataset. Returns the keys."""
    text = stamp.strftime("%Y%m%dT%H%M%SZ")
    keys: list[str] = []
    with tempfile.TemporaryDirectory(dir=staging) as work:
        work_dir = Path(work)
        export_dir = work_dir / "export"
        _export_database(db_path, export_dir)
        archive = work_dir / f"database-{text}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(export_dir, arcname="export")
        key = f"{prefix}/database-{text}.tar.gz"
        upload(archive, key)
        keys.append(key)

        if dataset_path.is_file() and not dataset_path.is_symlink():
            copy = work_dir / f"eval-{text}.jsonl"
            shutil.copyfile(dataset_path, copy)
            key = f"{prefix}/eval-{text}.jsonl"
            upload(copy, key)
            keys.append(key)
        else:
            log.info("backup.dataset_absent")
    log.info("backup.done", objects=len(keys))
    return keys


def _export_database(db_path: Path, out: Path) -> None:
    # DuckDB takes the path as a literal, so refuse anything that would end the quote.
    if "'" in str(out):
        raise ValueError("backup path must not contain a quote")
    con = connect_with_retry(db_path, read_only=True)
    try:
        con.execute(f"EXPORT DATABASE '{out}' (FORMAT PARQUET)")
    finally:
        con.close()
