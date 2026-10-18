"""Move old captures to object storage, then free the local copy (P1.6).

Captures are hostile content, so this module only moves regular files and never follows
a symbolic link. A local copy is deleted only after its upload has succeeded, so a
failed upload leaves the capture where it was. The in-progress job folder is never
touched: the watch loop still needs it.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from lookalike_hunter.logging import get_logger

log = get_logger(__name__)

# Folder the watch loop uses for job files and results in flight. Never archived.
JOBS_DIR = "_jobs"

Uploader = Callable[[Path, str], None]


@dataclass
class ArchiveStats:
    archived: int = 0
    failed: int = 0


def archive_captures(
    root: Path,
    prefix: str,
    older_than: timedelta,
    upload: Uploader,
    now: datetime,
) -> ArchiveStats:
    """Upload every capture file older than ``older_than``, then delete its local copy."""
    stats = ArchiveStats()
    cutoff = now.timestamp() - older_than.total_seconds()
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = Path(dirpath) / name
            relative = path.relative_to(root)
            if relative.parts[0] == JOBS_DIR:
                continue
            # Symbolic links and anything that is not a plain file are left alone.
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_mtime > cutoff:
                continue
            key = f"{prefix}/{relative.as_posix()}"
            try:
                upload(path, key)
            except Exception as exc:
                stats.failed += 1
                # The error may name the path; log its type only.
                log.error("archive.upload_failed", key=key, error=type(exc).__name__)
                continue
            path.unlink()
            stats.archived += 1
    return stats


def s3_uploader(bucket: str) -> Uploader:
    """Upload with the AWS CLI, which takes the instance role's credentials itself."""

    def upload(path: Path, key: str) -> None:
        # An argument list, never a shell: file names come from the hostile container.
        subprocess.run(
            ["aws", "s3", "cp", "--only-show-errors", str(path), f"s3://{bucket}/{key}"],
            check=True,
            capture_output=True,
            text=True,
        )

    return upload
