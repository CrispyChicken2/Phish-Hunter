"""DuckDB persistence for Certificates and Matches.

DuckDB allows a single writer process per file. The store therefore opens a
connection per flush and closes it immediately, so other processes (Streamlit
dashboard, notebooks) can open the file between flushes.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from lookalike_hunter.capture.models import CaptureResult
from lookalike_hunter.classify.schema import Verdict
from lookalike_hunter.ingest.parse import Certificate
from lookalike_hunter.scoring.scorer import Match


@dataclass(frozen=True, slots=True)
class PendingCapture:
    """An Alert awaiting a passive visit."""

    fqdn: str
    registered_domain: str
    brand: str
    score: float


@dataclass(frozen=True, slots=True)
class PendingClassification:
    """A stored capture awaiting a verdict."""

    capture_id: int
    fqdn: str
    status: str
    suspected_brand: str
    final_url: str | None = None
    screenshot_path: Path | None = None
    signals: dict[str, Any] | None = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    cert_sha256  VARCHAR PRIMARY KEY,
    seen_at      TIMESTAMPTZ NOT NULL,
    issuer_org   VARCHAR,
    not_before   TIMESTAMPTZ NOT NULL,
    not_after    TIMESTAMPTZ NOT NULL,
    ct_log       VARCHAR,
    all_domains  VARCHAR[] NOT NULL
);

-- One row per (Candidate, Brand); the first sighting wins.
CREATE TABLE IF NOT EXISTS matches (
    fqdn               VARCHAR NOT NULL,
    brand              VARCHAR NOT NULL,
    registered_domain  VARCHAR NOT NULL,
    score              DOUBLE NOT NULL,
    is_alert           BOOLEAN NOT NULL,
    features           JSON NOT NULL,
    cert_sha256        VARCHAR NOT NULL,
    first_seen_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (fqdn, brand)
);

-- One row per passive visit. Re-captures of the same host are kept as history.
CREATE SEQUENCE IF NOT EXISTS captures_id_seq;
CREATE TABLE IF NOT EXISTS captures (
    capture_id       BIGINT PRIMARY KEY DEFAULT nextval('captures_id_seq'),
    fqdn             VARCHAR NOT NULL,
    url              VARCHAR NOT NULL,
    status           VARCHAR NOT NULL,
    captured_at      TIMESTAMPTZ NOT NULL,
    duration_ms      BIGINT NOT NULL,
    final_url        VARCHAR,
    http_status      INTEGER,
    screenshot_path  VARCHAR,
    html_path        VARCHAR,
    signals          JSON,
    error            VARCHAR
);

-- One verdict per capture and backend, so a re-run with another model is kept
-- alongside the previous one for the Day 3 comparison.
CREATE SEQUENCE IF NOT EXISTS verdicts_id_seq;
CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id          BIGINT PRIMARY KEY DEFAULT nextval('verdicts_id_seq'),
    capture_id          BIGINT NOT NULL,
    fqdn                VARCHAR NOT NULL,
    backend             VARCHAR NOT NULL,
    model               VARCHAR,
    label               VARCHAR NOT NULL,
    confidence          DOUBLE NOT NULL,
    brand_impersonated  VARCHAR,
    evidence            VARCHAR,
    classified_at       TIMESTAMPTZ NOT NULL,
    latency_ms          BIGINT,
    error               VARCHAR,
    UNIQUE (capture_id, backend)
);
"""


class MatchStore:
    def __init__(self, db_path: Path, alert_threshold: float) -> None:
        self.db_path = db_path
        self.alert_threshold = alert_threshold
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with duckdb.connect(str(db_path)) as con:
            con.execute(SCHEMA)

    def write(self, rows: Sequence[tuple[Certificate, Match]]) -> int:
        """Persist Matches and their Certificates; returns the number of new Matches."""
        if not rows:
            return 0
        # A precert and its final cert often land in the same batch: keep the first.
        unique: dict[tuple[str, str], tuple[Certificate, Match]] = {}
        for c, m in rows:
            unique.setdefault((m.fqdn, m.brand), (c, m))
        rows = list(unique.values())
        certs = {c.sha256: c for c, _ in rows}
        with duckdb.connect(str(self.db_path)) as con:
            con.begin()
            con.executemany(
                "INSERT INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                [
                    (
                        c.sha256,
                        c.seen_at,
                        c.issuer_org,
                        c.not_before,
                        c.not_after,
                        c.ct_log,
                        list(c.domains),
                    )
                    for c in certs.values()
                ],
            )
            before = self._count(con)
            con.executemany(
                "INSERT INTO matches VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                [
                    (
                        m.fqdn,
                        m.brand,
                        m.registered_domain,
                        m.score,
                        m.score >= self.alert_threshold,
                        json.dumps(asdict(m.features)),
                        c.sha256,
                        c.seen_at,
                    )
                    for c, m in rows
                ],
            )
            inserted = self._count(con) - before
            con.commit()
        return inserted

    def pending_captures(self, limit: int, recapture_after_h: float) -> list[PendingCapture]:
        """Highest-scoring alerts not captured recently, one row per hostname.

        Grouped by hostname because one host can alert for several brands; the
        capture is of the site, not of the brand match.
        """
        with duckdb.connect(str(self.db_path), read_only=True) as con:
            rows = con.execute(
                """
                SELECT m.fqdn, any_value(m.registered_domain), arg_max(m.brand, m.score),
                       max(m.score)
                FROM matches m
                WHERE m.is_alert
                  AND NOT EXISTS (
                      SELECT 1 FROM captures c
                      WHERE c.fqdn = m.fqdn
                        AND c.captured_at > now() - INTERVAL (?) HOUR
                  )
                GROUP BY m.fqdn
                ORDER BY max(m.score) DESC, min(m.first_seen_at) DESC
                LIMIT ?
                """,
                [recapture_after_h, limit],
            ).fetchall()
        return [PendingCapture(f, d, b, float(s)) for f, d, b, s in rows]

    def save_capture(self, result: CaptureResult) -> None:
        with duckdb.connect(str(self.db_path)) as con:
            con.execute(
                """
                INSERT INTO captures
                    (fqdn, url, status, captured_at, duration_ms, final_url, http_status,
                     screenshot_path, html_path, signals, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    result.fqdn,
                    result.url,
                    str(result.status),
                    result.captured_at,
                    result.duration_ms,
                    result.final_url,
                    result.http_status,
                    str(result.screenshot_path) if result.screenshot_path else None,
                    str(result.html_path) if result.html_path else None,
                    json.dumps(asdict(result.signals)) if result.signals else None,
                    result.error,
                ],
            )

    def pending_classifications(self, limit: int, backend: str) -> list[PendingClassification]:
        """Captures with no verdict yet from this backend, newest first."""
        with duckdb.connect(str(self.db_path), read_only=True) as con:
            rows = con.execute(
                """
                SELECT c.capture_id, c.fqdn, c.status, c.final_url, c.screenshot_path, c.signals,
                       (SELECT arg_max(m.brand, m.score) FROM matches m WHERE m.fqdn = c.fqdn)
                FROM captures c
                WHERE NOT EXISTS (
                    SELECT 1 FROM verdicts v
                    WHERE v.capture_id = c.capture_id AND v.backend = ?
                )
                ORDER BY c.captured_at DESC
                LIMIT ?
                """,
                [backend, limit],
            ).fetchall()
        return [
            PendingClassification(
                capture_id=int(r[0]),
                fqdn=r[1],
                status=r[2],
                final_url=r[3],
                screenshot_path=Path(r[4]) if r[4] else None,
                signals=json.loads(r[5]) if r[5] else None,
                suspected_brand=r[6] or "unknown",
            )
            for r in rows
        ]

    def save_verdict(
        self,
        capture_id: int,
        fqdn: str,
        backend: str,
        model: str | None,
        verdict: Verdict | None,
        classified_at: datetime,
        latency_ms: int | None = None,
        error: str | None = None,
    ) -> None:
        """Store a verdict, or a failure row so the capture is not retried forever."""
        with duckdb.connect(str(self.db_path)) as con:
            con.execute(
                """
                INSERT INTO verdicts
                    (capture_id, fqdn, backend, model, label, confidence, brand_impersonated,
                     evidence, classified_at, latency_ms, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                [
                    capture_id,
                    fqdn,
                    backend,
                    model,
                    str(verdict.label) if verdict else "error",
                    verdict.confidence if verdict else 0.0,
                    verdict.brand_impersonated if verdict else None,
                    verdict.evidence if verdict else None,
                    classified_at,
                    latency_ms,
                    error,
                ],
            )

    @staticmethod
    def _count(con: duckdb.DuckDBPyConnection) -> int:
        row = con.execute("SELECT count(*) FROM matches").fetchone()
        assert row is not None
        return int(row[0])
