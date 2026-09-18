"""DuckDB persistence for Certificates and Matches.

DuckDB allows a single writer process per file. The store therefore opens a
connection per flush and closes it immediately, so other processes (Streamlit
dashboard, notebooks) can open the file between flushes.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

import duckdb

from lookalike_hunter.ingest.parse import Certificate
from lookalike_hunter.scoring.scorer import Match

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

    @staticmethod
    def _count(con: duckdb.DuckDBPyConnection) -> int:
        row = con.execute("SELECT count(*) FROM matches").fetchone()
        assert row is not None
        return int(row[0])
