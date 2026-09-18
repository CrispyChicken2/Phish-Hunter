import json
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from lookalike_hunter.ingest.parse import Certificate
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.scoring.scorer import Match, MatchFeatures

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


def cert(sha: str = "ab" * 32) -> Certificate:
    return Certificate(sha, NOW, "Let's Encrypt", NOW, NOW, "log", ("paypa1.com",))


def match(fqdn: str = "paypa1.com", score: float = 0.9) -> Match:
    return Match(fqdn, "paypa1.com", "paypal", score, MatchFeatures(homoglyph=True))


def test_write_persists_and_dedupes(tmp_path: Path) -> None:
    db = tmp_path / "sub" / "t.duckdb"
    store = MatchStore(db, alert_threshold=0.7)

    assert store.write([(cert(), match()), (cert(), match("low.paypa1.com", 0.5))]) == 2
    assert store.write([(cert(), match())]) == 0  # same (fqdn, brand): first sighting wins

    with duckdb.connect(str(db), read_only=True) as con:
        rows = con.execute("SELECT fqdn, is_alert, features FROM matches ORDER BY fqdn").fetchall()
        n_certs = con.execute("SELECT count(*) FROM certificates").fetchone()
    assert [(r[0], r[1]) for r in rows] == [("low.paypa1.com", False), ("paypa1.com", True)]
    assert json.loads(rows[1][2])["homoglyph"] is True
    assert n_certs == (1,)


def test_duplicates_within_one_batch(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    assert store.write([(cert("aa" * 32), match()), (cert("bb" * 32), match())]) == 1


def test_write_empty_is_noop(tmp_path: Path) -> None:
    assert MatchStore(tmp_path / "t.duckdb", 0.7).write([]) == 0


def test_file_is_released_between_writes(tmp_path: Path) -> None:
    db = tmp_path / "t.duckdb"
    store = MatchStore(db, 0.7)
    store.write([(cert(), match())])
    # A second process-style connection must be able to open the file.
    with duckdb.connect(str(db)) as con:
        assert con.execute("SELECT count(*) FROM matches").fetchone() == (1,)
