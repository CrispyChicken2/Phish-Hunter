"""Analyst labels from the dashboard, written into the evaluation dataset.

The benchmark's weakest point is who labelled it: the same agent that built the
system. Every finding an analyst confirms or corrects in the dashboard becomes a
human label here, so the evaluation grows, and becomes more independent, simply
through use. ``labelled_by`` keeps the two kinds apart so a report can say how
many of its labels a human gave.

The file is the benchmark, so it is edited with care: one line per site, a
relabel replaces that site's line in place, every other line is left byte for
byte, a label someone else gave is kept in the note rather than silently lost,
and the file is replaced atomically so a crash cannot leave half of it.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from lookalike_hunter.capture.policy import is_valid_hostname
from lookalike_hunter.classify.schema import Label

HUMAN = "human"

# What a site *is*. "unreachable" describes our visit, not the site (see
# eval/dataset.py), so an analyst cannot assign it.
REVIEWABLE_LABELS: tuple[Label, ...] = (
    Label.PHISHING,
    Label.PARKED,
    Label.LEGITIMATE,
    Label.UNKNOWN,
)

_HEADER = (
    '# Candidate sites for evaluation. Set "expected" on every line;\n'
    "# see docs/labelling-protocol.md. Unlabelled entries are refused.\n"
)


@dataclass(frozen=True, slots=True)
class ExistingLabel:
    expected: str | None
    labelled_by: str | None
    labelled_at: str | None


def current_labels(path: Path) -> dict[str, ExistingLabel]:
    """Each site's label as the file has it, for showing next to a finding."""
    labels: dict[str, ExistingLabel] = {}
    if not path.exists():
        return labels
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = _entry(line)
        if payload is not None:
            labels[str(payload["fqdn"]).strip().lower()] = ExistingLabel(
                expected=payload.get("expected"),
                labelled_by=payload.get("labelled_by"),
                labelled_at=payload.get("labelled_at"),
            )
    return labels


def record_label(
    path: Path,
    fqdn: str,
    label: Label,
    *,
    brand: str | None = None,
    suggestion: str | None = None,
    today: date | None = None,
) -> ExistingLabel | None:
    """Set ``fqdn``'s label as a human's; returns what it was before, if anything.

    ``fqdn`` comes from the database, which the capture side writes, so it is
    checked like any other hostile hostname before it enters the benchmark.
    """
    if label not in REVIEWABLE_LABELS:
        raise ValueError(f"{label} describes a visit, not a site, and cannot be a label")
    fqdn = fqdn.strip().lower()
    if not is_valid_hostname(fqdn):
        raise ValueError(f"not a hostname: {fqdn[:80]!r}")
    stamp = (today or datetime.now(UTC).date()).isoformat()

    raw = path.read_bytes().decode("utf-8") if path.exists() else ""
    # Keep the file's own line endings (a Windows checkout has CRLF), so every
    # line not being relabelled really is left byte for byte.
    newline = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.splitlines()
    previous: ExistingLabel | None = None
    for index, line in enumerate(lines):
        payload = _entry(line)
        if payload is None or str(payload["fqdn"]).strip().lower() != fqdn:
            continue
        previous = ExistingLabel(
            payload.get("expected"), payload.get("labelled_by"), payload.get("labelled_at")
        )
        lines[index] = json.dumps(_relabelled(payload, label, previous, stamp), sort_keys=True)
        break
    else:
        if not lines:
            lines = _HEADER.splitlines()
        lines.append(
            json.dumps(
                {
                    "fqdn": fqdn,
                    "expected": str(label),
                    "suggestion": suggestion,
                    "brand": brand,
                    # Dashboard findings are what the CT pipeline alerted on.
                    "source": "alerts",
                    "labelled_at": stamp,
                    "labelled_by": HUMAN,
                    "label_basis": "screenshot",
                    "note": None,
                },
                sort_keys=True,
            )
        )
    _replace(path, newline.join(lines) + newline)
    return previous


def _relabelled(
    payload: dict[str, Any], label: Label, previous: ExistingLabel, stamp: str
) -> dict[str, Any]:
    updated = {
        **payload,
        "expected": str(label),
        "labelled_by": HUMAN,
        "labelled_at": stamp,
        "label_basis": "screenshot",
    }
    # Someone else's label is evidence too; keep it rather than overwrite it.
    if previous.labelled_by != HUMAN and previous.expected not in (None, str(label)):
        was = f"relabelled by a human; was {previous.expected} ({previous.labelled_by or '?'})"
        updated["note"] = f"{payload['note']}; {was}" if payload.get("note") else was
    return updated


def _entry(line: str) -> dict[str, Any] | None:
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) and "fqdn" in payload else None


def _replace(path: Path, text: str) -> None:
    """Write the whole file atomically: the new version or the old one, never half."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
