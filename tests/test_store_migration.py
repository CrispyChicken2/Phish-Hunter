"""The verdicts migration runs on every database open, so it has to be tested.

It rebuilds a table holding every result the project has produced. Verified by
hand once is not enough: a mistake here silently loses the evaluation data
everything else rests on.
"""

from datetime import UTC, datetime
from pathlib import Path

import duckdb
import structlog.testing

from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.ingest.store import MatchStore

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)

# The schema as it shipped before models were part of the key, and before token
# accounting existed. Two verdicts for the same capture could not coexist.
OLD_SCHEMA = """
CREATE SEQUENCE IF NOT EXISTS verdicts_id_seq;
CREATE TABLE verdicts (
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


def make_old_database(path: Path, rows: int = 3) -> None:
    with duckdb.connect(str(path)) as con:
        con.execute(OLD_SCHEMA)
        for index in range(rows):
            con.execute(
                """
                INSERT INTO verdicts
                    (capture_id, fqdn, backend, model, label, confidence,
                     brand_impersonated, evidence, classified_at, latency_ms, error)
                VALUES (?, ?, 'mistral', 'old-model', 'parked', 0.9, NULL, 'e', ?, 100, NULL)
                """,
                [index + 1, f"site{index}.test", NOW],
            )


def test_migration_preserves_every_row(tmp_path: Path) -> None:
    db = tmp_path / "old.duckdb"
    make_old_database(db, rows=5)

    MatchStore(db, 0.7)  # opening runs the migration

    with duckdb.connect(str(db), read_only=True) as con:
        rows = con.execute("SELECT fqdn, label, latency_ms FROM verdicts ORDER BY fqdn").fetchall()
    assert len(rows) == 5
    assert rows[0] == ("site0.test", "parked", 100)  # values survive, not just the count


def test_migration_widens_the_key_so_models_coexist(tmp_path: Path) -> None:
    """The point of the migration: a second model must no longer be discarded."""
    db = tmp_path / "old.duckdb"
    make_old_database(db, rows=1)
    store = MatchStore(db, 0.7)

    verdict = Verdict(label=Label.PHISHING, confidence=0.8, evidence="x")
    written = store.save_verdict(1, "site0.test", "mistral", "new-model", verdict, NOW)

    assert written is True
    with duckdb.connect(str(db), read_only=True) as con:
        models = con.execute(
            "SELECT model FROM verdicts WHERE capture_id = 1 ORDER BY model"
        ).fetchall()
    assert models == [("new-model",), ("old-model",)]


def test_migration_adds_the_accounting_columns(tmp_path: Path) -> None:
    db = tmp_path / "old.duckdb"
    make_old_database(db, rows=1)

    MatchStore(db, 0.7)

    with duckdb.connect(str(db), read_only=True) as con:
        columns = {row[0] for row in con.execute("DESCRIBE verdicts").fetchall()}
    assert {"prompt_tokens", "completion_tokens", "cost_usd"} <= columns


def test_migration_is_idempotent(tmp_path: Path) -> None:
    """It runs on every open, so running it twice must not duplicate or drop rows."""
    db = tmp_path / "old.duckdb"
    make_old_database(db, rows=3)

    for _ in range(3):
        MatchStore(db, 0.7)

    with duckdb.connect(str(db), read_only=True) as con:
        assert con.execute("SELECT count(*) FROM verdicts").fetchone() == (3,)
        leftovers = con.execute(
            "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'verdicts_old'"
        ).fetchone()
    assert leftovers == (0,)  # the temporary table is cleaned up


def test_a_fresh_database_needs_no_migration(tmp_path: Path) -> None:
    db = tmp_path / "new.duckdb"
    with structlog.testing.capture_logs() as logs:
        MatchStore(db, 0.7)
        MatchStore(db, 0.7)  # second open must be a no-op

    # The table is rebuilt only when its key is the old one, not on every open.
    assert not [e for e in logs if e["event"] == "store.migrating_verdicts_uniqueness"]

    with duckdb.connect(str(db), read_only=True) as con:
        assert con.execute("SELECT count(*) FROM verdicts").fetchone() == (0,)
