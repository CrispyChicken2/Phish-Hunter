"""Recompute stored Matches with the current scoring configuration (P3.1).

A Match is scored once, when its certificate is ingested, and the stored score is
never touched again. After the weights or the alert threshold change, older rows
keep figures the current configuration would not produce, so `alerts` and the
capture queue mix two scorings. This brings every row up to date.

Rows are updated, never deleted. A row that now scores below the storage floor
keeps its real new score and stops being an Alert: deleting it would lose its
first sighting and its link to captures and verdicts, and could not be undone.
Hostnames that never reached the storage floor were not stored, so they cannot be
reconsidered here.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from lookalike_hunter.ingest.store import connect_with_retry
from lookalike_hunter.scoring.scorer import Scorer


@dataclass(frozen=True, slots=True)
class ScoreChange:
    fqdn: str
    brand: str
    old_score: float
    new_score: float
    was_alert: bool
    is_alert: bool
    features: dict[str, Any]


@dataclass(slots=True)
class RescoreReport:
    checked: int = 0
    changes: list[ScoreChange] = field(default_factory=list)
    applied: bool = False

    @property
    def now_alerting(self) -> list[ScoreChange]:
        return [c for c in self.changes if c.is_alert and not c.was_alert]

    @property
    def no_longer_alerting(self) -> list[ScoreChange]:
        return [c for c in self.changes if c.was_alert and not c.is_alert]


def _stored_features(raw: Any) -> Any:
    return json.loads(raw) if isinstance(raw, str) else raw


def rescore(
    db_path: Path, scorer: Scorer, alert_threshold: float, *, apply: bool = False
) -> RescoreReport:
    """Score every stored Match again; write the differences only if ``apply``."""
    with connect_with_retry(db_path, read_only=True) as con:
        rows = con.execute(
            """
            SELECT m.fqdn, m.brand, m.score, m.is_alert, m.features, c.issuer_org
            FROM matches m LEFT JOIN certificates c USING (cert_sha256)
            ORDER BY m.fqdn, m.brand
            """
        ).fetchall()

    report = RescoreReport(checked=len(rows))
    current: dict[tuple[str, str | None], dict[str, Any]] = {}
    for fqdn, brand, old_score, was_alert, stored, issuer in rows:
        key = (fqdn, issuer)
        if key not in current:
            # Floor 0: every Brand's real score, including those now below the floor.
            current[key] = {m.brand: m for m in scorer.score(fqdn, issuer, floor=0.0)}
        match = current[key].get(brand)
        # No score at all: the brand was removed, or this is now one of its domains.
        new_score = match.score if match else 0.0
        features = asdict(match.features) if match else _stored_features(stored)
        is_alert = new_score >= alert_threshold
        if (
            abs(new_score - old_score) > 1e-9
            or is_alert != was_alert
            or features != _stored_features(stored)
        ):
            report.changes.append(
                ScoreChange(fqdn, brand, old_score, new_score, was_alert, is_alert, features)
            )

    if apply and report.changes:
        with connect_with_retry(db_path) as con:
            con.begin()
            con.executemany(
                "UPDATE matches SET score = ?, is_alert = ?, features = ? "
                "WHERE fqdn = ? AND brand = ?",
                [
                    (c.new_score, c.is_alert, json.dumps(c.features), c.fqdn, c.brand)
                    for c in report.changes
                ],
            )
            con.commit()
    report.applied = apply
    return report
