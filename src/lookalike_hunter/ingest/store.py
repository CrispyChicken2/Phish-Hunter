"""DuckDB persistence for Certificates and Matches.

DuckDB allows a single writer process per file. The store therefore opens a
connection per flush and closes it immediately, so other processes (Streamlit
dashboard, notebooks) can open the file between flushes.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from lookalike_hunter.capture.models import CaptureResult
from lookalike_hunter.classify.schema import Verdict
from lookalike_hunter.ingest.parse import Certificate
from lookalike_hunter.logging import get_logger
from lookalike_hunter.scoring.scorer import Match

log = get_logger(__name__)

# DuckDB allows one writer per file. Collection runs capture while ingestion is
# flushing, so a collision is routine rather than exceptional: measured at 9 of 11
# capture cycles. The loser of the race waits and retries instead of failing.
#
# Contention is detected by exclusion, not by matching the message: the operating
# system localises it (a French Windows says "le processus ne peut pas acceder au
# fichier car ce fichier est utilise par un autre processus", a Linux container says
# "Permission denied"), so a positive-match list silently stops working depending on
# the machine. Only failures that retrying cannot possibly fix are re-raised at once.
_PERMANENT_MARKERS = (
    "corrupt",
    "not a valid",
    "unsupported",
    "no such file",
    "read-only",
    "out of memory",
)


class LockContentionError(RuntimeError):
    """The database stayed locked by another process for the whole retry budget."""


def _is_permanent(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(marker in message for marker in _PERMANENT_MARKERS)


def connect_with_retry(
    db_path: Path,
    *,
    read_only: bool = False,
    attempts: int = 6,
    base_delay_s: float = 0.25,
    connect: Callable[..., Any] = duckdb.connect,
) -> Any:
    """Open the database, waiting out a writer held by another process.

    Only lock contention is retried; a corrupt or unreadable file fails immediately,
    because retrying that would just hide the real problem.
    """
    for attempt in range(1, attempts + 1):
        try:
            return connect(str(db_path), read_only=read_only)
        except duckdb.IOException as exc:
            if _is_permanent(exc):
                raise
            if attempt == attempts:
                raise LockContentionError(
                    f"{db_path} stayed locked by another process after {attempts} attempts: {exc}"
                ) from exc
            delay = base_delay_s * 2 ** (attempt - 1)
            log.debug("store.lock_retry", db=str(db_path), attempt=attempt, retry_in_s=delay)
            time.sleep(delay)
    raise AssertionError("unreachable")


@dataclass(frozen=True, slots=True)
class PendingCapture:
    """An Alert awaiting a passive visit."""

    fqdn: str
    registered_domain: str
    brand: str
    score: float


@dataclass(frozen=True, slots=True)
class PendingAlert:
    """A Verdict that meets the alert policy and has not been announced yet."""

    verdict_id: int
    fqdn: str
    label: str
    confidence: float
    score: float
    brand: str | None
    evidence: str | None
    screenshot_path: str | None
    final_url: str | None
    classified_at: datetime


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
--
-- Consequence worth knowing: a stored score is never updated. After the scoring
-- weights change, rows written earlier keep their old score, so `alerts` can show
-- figures the current configuration would not produce. Evaluation is unaffected,
-- because it re-scores from the hostname rather than reading these rows.
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

"""

SCHEMA_VERDICTS = """
-- One verdict per capture, backend and model. The model must be part of the key:
-- without it, a second model's verdicts collide with the first's and ON CONFLICT
-- DO NOTHING discards them silently, so a comparison run stores nothing while
-- reporting success. That happened.
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
    prompt_tokens       BIGINT,
    completion_tokens   BIGINT,
    cost_usd            DOUBLE,
    error               VARCHAR,
    alerted_at          TIMESTAMPTZ,
    UNIQUE (capture_id, backend, model)
);
"""


# Columns added after the first release, applied to existing databases on open.
MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("prompt_tokens", "BIGINT"),
    ("completion_tokens", "BIGINT"),
    ("cost_usd", "DOUBLE"),
    ("alerted_at", "TIMESTAMPTZ"),
)


def _widen_verdict_uniqueness(con: duckdb.DuckDBPyConnection) -> None:
    """Make (capture_id, backend, model) unique on databases created before models.

    The original constraint was (capture_id, backend). With ON CONFLICT DO NOTHING
    that silently discarded every verdict from a second model: runs reported
    success while storing nothing, and a model comparison showed no data. A
    constraint cannot be altered in place, so the table is rebuilt.
    """
    definition = con.execute(
        "SELECT sql FROM duckdb_tables() WHERE table_name = 'verdicts'"
    ).fetchone()
    # Both sides without spaces: DuckDB's own rendering of the constraint has them,
    # and comparing a spaced needle to a stripped haystack never matched, which
    # rebuilt the whole table on every open.
    if definition is None or "UNIQUE(capture_id,backend,model)" in definition[0].replace(" ", ""):
        return
    log.info("store.migrating_verdicts_uniqueness")
    con.execute("BEGIN TRANSACTION")
    con.execute("ALTER TABLE verdicts RENAME TO verdicts_old")
    con.execute(SCHEMA_VERDICTS)
    con.execute(
        """
        INSERT INTO verdicts
            (verdict_id, capture_id, fqdn, backend, model, label, confidence,
             brand_impersonated, evidence, classified_at, latency_ms, prompt_tokens,
             completion_tokens, cost_usd, error, alerted_at)
        SELECT verdict_id, capture_id, fqdn, backend, model, label, confidence,
               brand_impersonated, evidence, classified_at, latency_ms, prompt_tokens,
               completion_tokens, cost_usd, error, alerted_at
        FROM verdicts_old
        """
    )
    con.execute("DROP TABLE verdicts_old")
    con.execute("COMMIT")


class MatchStore:
    def __init__(self, db_path: Path, alert_threshold: float) -> None:
        self.db_path = db_path
        self.alert_threshold = alert_threshold
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with connect_with_retry(db_path) as con:
            con.execute(SCHEMA)
            con.execute(SCHEMA_VERDICTS)
            # CREATE TABLE IF NOT EXISTS leaves an older database without the newer
            # columns, so a running install would break on the next write.
            for column, sql_type in MIGRATIONS:
                con.execute(f"ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS {column} {sql_type}")
            _widen_verdict_uniqueness(con)

    def write(self, rows: Sequence[tuple[Certificate, Match]]) -> int:
        """Persist Matches and their Certificates; returns the number of new Matches.

        Conflicts are skipped rather than overwritten, and the count returned tells
        the caller how many rows were actually new. Certificates dedupe on their
        own hash, so a skipped one carries identical content; Matches keep their
        first score (see the schema note).
        """
        if not rows:
            return 0
        # A precert and its final cert often land in the same batch: keep the first.
        unique: dict[tuple[str, str], tuple[Certificate, Match]] = {}
        for c, m in rows:
            unique.setdefault((m.fqdn, m.brand), (c, m))
        rows = list(unique.values())
        certs = {c.sha256: c for c, _ in rows}
        with connect_with_retry(self.db_path) as con:
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
        with connect_with_retry(self.db_path, read_only=True) as con:
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

    def uncaptured(self, fqdns: Sequence[str], recapture_after_h: float) -> list[str]:
        """Of these hostnames, the ones with no recent Capture, order preserved.

        Used to capture dataset entries that never alerted: a site hosted on
        github.io or S3 carries no brand lookalike, so it never reaches the
        matches table, yet it still needs a screenshot to be labelled.
        """
        if not fqdns:
            return []
        with connect_with_retry(self.db_path, read_only=True) as con:
            rows = con.execute(
                """
                SELECT DISTINCT fqdn FROM captures
                WHERE fqdn IN (SELECT unnest(?)) AND captured_at > now() - INTERVAL (?) HOUR
                """,
                [list(fqdns), recapture_after_h],
            ).fetchall()
        recent = {row[0] for row in rows}
        return [fqdn for fqdn in fqdns if fqdn not in recent]

    def save_capture(self, result: CaptureResult) -> None:
        with connect_with_retry(self.db_path) as con:
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
                    # Forward slashes whatever the OS: Windows reads them, Linux
                    # does not read backslashes, and the DB moves between both.
                    result.screenshot_path.as_posix() if result.screenshot_path else None,
                    result.html_path.as_posix() if result.html_path else None,
                    json.dumps(asdict(result.signals)) if result.signals else None,
                    result.error,
                ],
            )

    def pending_classifications(
        self, limit: int, backend: str, model: str | None = None
    ) -> list[PendingClassification]:
        """Captures with no verdict yet from this backend and model, newest first.

        Model-aware so a second model re-judges the same captures instead of
        inheriting the first model's answers.
        """
        with connect_with_retry(self.db_path, read_only=True) as con:
            rows = con.execute(
                """
                SELECT c.capture_id, c.fqdn, c.status, c.final_url, c.screenshot_path, c.signals,
                       (SELECT arg_max(m.brand, m.score) FROM matches m WHERE m.fqdn = c.fqdn)
                FROM captures c
                WHERE NOT EXISTS (
                    SELECT 1 FROM verdicts v
                    WHERE v.capture_id = c.capture_id AND v.backend = ?
                      AND (? IS NULL OR v.model IS NOT DISTINCT FROM ?)
                )
                ORDER BY c.captured_at DESC
                LIMIT ?
                """,
                [backend, model, model, limit],
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
    ) -> bool:
        """Store a verdict, or a failure row so the capture is not retried forever.

        Returns whether a row was written. A conflicting row is skipped rather than
        overwritten, and the caller is told: a silent discard once made a whole
        model comparison report success while storing nothing.
        """
        usage = verdict.usage if verdict else None
        with connect_with_retry(self.db_path) as con:
            inserted = con.execute(
                """
                INSERT INTO verdicts
                    (capture_id, fqdn, backend, model, label, confidence, brand_impersonated,
                     evidence, classified_at, latency_ms, prompt_tokens, completion_tokens,
                     cost_usd, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                RETURNING verdict_id
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
                    usage.prompt_tokens if usage else None,
                    usage.completion_tokens if usage else None,
                    usage.cost_usd if usage else None,
                    error,
                ],
            )
            # RETURNING yields nothing when ON CONFLICT skipped the row.
            written = bool(inserted.fetchall())
        if not written:
            log.warning(
                "store.verdict_not_written",
                fqdn=fqdn,
                backend=backend,
                model=model,
                reason="a verdict already exists for this capture, backend and model",
            )
        return written

    def pending_alerts(
        self, labels: Sequence[str], min_confidence: float, limit: int
    ) -> list[PendingAlert]:
        """Verdicts matching the policy that nobody has been told about yet."""
        with connect_with_retry(self.db_path, read_only=True) as con:
            rows = con.execute(
                """
                SELECT v.verdict_id, v.fqdn, v.label, v.confidence,
                       coalesce((SELECT max(m.score) FROM matches m WHERE m.fqdn = v.fqdn), 0.0),
                       v.brand_impersonated, v.evidence, c.screenshot_path, c.final_url,
                       v.classified_at
                FROM verdicts v JOIN captures c USING (capture_id)
                WHERE v.alerted_at IS NULL
                  AND v.label IN (SELECT unnest(?))
                  AND v.confidence >= ?
                ORDER BY v.confidence DESC, v.verdict_id DESC
                LIMIT ?
                """,
                [list(labels), min_confidence, limit],
            ).fetchall()
        return [PendingAlert(*row) for row in rows]

    def mark_alerted(self, verdict_id: int, when: datetime) -> None:
        """Record that a finding has been announced, so it is announced once."""
        with connect_with_retry(self.db_path) as con:
            con.execute(
                "UPDATE verdicts SET alerted_at = ? WHERE verdict_id = ?", [when, verdict_id]
            )

    def clear_verdicts(
        self, backend: str, model: str | None = None, limit: int | None = None
    ) -> int:
        """Drop stored verdicts so their captures are classified again.

        Used to measure a prompt or model change against the same sites; without
        it a rerun would silently reuse the answers the change was meant to alter.
        """
        with connect_with_retry(self.db_path) as con:
            rows = con.execute(
                """
                SELECT verdict_id FROM verdicts
                WHERE backend = ? AND (? IS NULL OR model = ?)
                ORDER BY verdict_id DESC LIMIT ?
                """,
                [backend, model, model, limit if limit is not None else 1_000_000],
            ).fetchall()
            ids = [row[0] for row in rows]
            if ids:
                con.execute("DELETE FROM verdicts WHERE verdict_id IN (SELECT unnest(?))", [ids])
        return len(ids)

    def clear_failed_verdicts(self, backend: str) -> int:
        """Drop error rows so their captures are classified again."""
        with connect_with_retry(self.db_path) as con:
            before = con.execute("SELECT count(*) FROM verdicts").fetchone()
            con.execute("DELETE FROM verdicts WHERE backend = ? AND label = 'error'", [backend])
            after = con.execute("SELECT count(*) FROM verdicts").fetchone()
        assert before is not None and after is not None
        return int(before[0]) - int(after[0])

    @staticmethod
    def _count(con: duckdb.DuckDBPyConnection) -> int:
        row = con.execute("SELECT count(*) FROM matches").fetchone()
        assert row is not None
        return int(row[0])
