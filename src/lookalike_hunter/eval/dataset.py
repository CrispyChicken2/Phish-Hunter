"""The labelled dataset the evaluation measures against.

One JSON object per line. JSON Lines rather than CSV because a label change shows
up as a one-line diff in review, and because notes and hostnames contain commas,
quotes and non-ASCII characters that CSV handles badly.

Ground truth lives here and nowhere else. A feed's own label is recorded in
``source`` as provenance: trusting it would make the phishing class circular,
measuring agreement with the feed rather than accuracy.

``expected`` says what a site *is*; whether we could reach it is a separate fact,
taken from the Capture. Conflating them corrupts both measurements: a phishing
domain taken down before we visited is still a site the Scorer should flag, so
labelling it "unreachable" would penalise a correct detection, while measuring the
vision model on a site it cannot see would be meaningless. ``label_basis`` records
how the label was reached, so a report can separate labels made from a screenshot
from those resting on feed provenance alone.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal, cast

from lookalike_hunter.classify.schema import Label


class DatasetError(ValueError):
    """A dataset file that cannot be trusted to mean what it says."""


class UnlabelledSiteError(DatasetError):
    """The builder produced this entry and no human has labelled it yet."""


# How a label was arrived at. "screenshot" is the standard: a human looked at the
# page. "feed" means the site was gone before we could look and the class rests on
# the feed listing it, which is weaker evidence and is reported separately.
LabelBasis = Literal["screenshot", "feed"]


@dataclass(frozen=True, slots=True)
class LabelledSite:
    fqdn: str
    expected: Label
    source: str
    labelled_at: date
    brand: str | None = None
    note: str | None = None
    label_basis: LabelBasis = "screenshot"
    # "human" (an analyst, e.g. from the dashboard) or "agent"; None on old lines.
    labelled_by: str | None = None


def _parse_line(raw: str, path: Path, line_number: int, allow_unlabelled: bool) -> LabelledSite:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DatasetError(f"{path}:{line_number}: not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise DatasetError(f"{path}:{line_number}: expected a JSON object")

    missing = {"fqdn", "expected", "source", "labelled_at"} - payload.keys()
    if missing:
        raise DatasetError(f"{path}:{line_number}: missing field(s) {sorted(missing)}")

    if payload["expected"] is None:
        if not allow_unlabelled:
            raise UnlabelledSiteError(
                f"{path}:{line_number}: {payload['fqdn']} has no label yet. "
                'Set "expected" for every candidate; see docs/labelling-protocol.md'
            )
        # Reviewing tools need to see the candidate; evaluation never does.
        return LabelledSite(
            fqdn=str(payload["fqdn"]).strip().lower(),
            expected=Label.UNKNOWN,
            source=str(payload["source"]),
            labelled_at=date.fromisoformat(str(payload["labelled_at"])),
            brand=payload.get("brand"),
            note=payload.get("note"),
        )
    try:
        expected = Label(payload["expected"])
    except ValueError as exc:
        raise DatasetError(
            f"{path}:{line_number}: unknown label {payload['expected']!r}; "
            f"expected one of {[label.value for label in Label]}"
        ) from exc
    try:
        labelled_at = date.fromisoformat(str(payload["labelled_at"]))
    except ValueError as exc:
        raise DatasetError(f"{path}:{line_number}: labelled_at must be an ISO date: {exc}") from exc

    basis = payload.get("label_basis", "screenshot")
    if basis not in ("screenshot", "feed"):
        raise DatasetError(
            f"{path}:{line_number}: label_basis must be 'screenshot' or 'feed', got {basis!r}"
        )

    return LabelledSite(
        fqdn=str(payload["fqdn"]).strip().lower(),
        expected=expected,
        source=str(payload["source"]),
        labelled_at=labelled_at,
        brand=payload.get("brand"),
        note=payload.get("note"),
        label_basis=cast(LabelBasis, basis),
        labelled_by=payload.get("labelled_by"),
    )


def iter_dataset(path: Path, *, allow_unlabelled: bool = False) -> Iterator[LabelledSite]:
    """Yield each labelled site, naming the offending line when one is malformed."""
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if raw.strip() and not raw.lstrip().startswith("#"):
                yield _parse_line(raw, path, line_number, allow_unlabelled)


def load_dataset(path: Path) -> list[LabelledSite]:
    """Load the dataset, rejecting duplicates so one site cannot be counted twice."""
    sites = list(iter_dataset(path))
    seen: dict[str, int] = {}
    for position, site in enumerate(sites, start=1):
        if site.fqdn in seen:
            raise DatasetError(
                f"{path}: {site.fqdn} appears twice (entries {seen[site.fqdn]} and {position})"
            )
        seen[site.fqdn] = position
    if not sites:
        raise DatasetError(f"{path}: dataset is empty")
    return sites
