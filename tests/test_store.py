import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.signals import PageSignals
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


def capture(
    fqdn: str = "paypa1.com", when: datetime = NOW, status: CaptureStatus = CaptureStatus.OK
) -> CaptureResult:
    return CaptureResult(
        fqdn=fqdn,
        url=f"https://{fqdn}/",
        status=status,
        captured_at=when,
        duration_ms=1200,
        final_url=f"https://{fqdn}/login",
        http_status=200,
        signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
    )


def test_pending_captures_ranks_alerts_by_score(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    store.write(
        [
            (cert("aa" * 32), match("low-alert.com", 0.72)),
            (cert("bb" * 32), match("high-alert.com", 0.95)),
            (cert("cc" * 32), match("below-threshold.com", 0.5)),
        ]
    )

    pending = store.pending_captures(limit=10, recapture_after_h=24)

    assert [p.fqdn for p in pending] == ["high-alert.com", "low-alert.com"]
    assert pending[0].brand == "paypal"


def test_recent_capture_excludes_host_but_old_one_does_not(tmp_path: Path) -> None:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    store.write([(cert(), match("a.com", 0.9)), (cert("bb" * 32), match("b.com", 0.8))])

    store.save_capture(capture("a.com", when=datetime.now(UTC)))
    store.save_capture(capture("b.com", when=datetime.now(UTC) - timedelta(hours=48)))

    assert [p.fqdn for p in store.pending_captures(10, recapture_after_h=24)] == ["b.com"]


def test_save_capture_persists_signals_and_errors(tmp_path: Path) -> None:
    db = tmp_path / "t.duckdb"
    store = MatchStore(db, 0.7)
    store.save_capture(capture())
    store.save_capture(
        CaptureResult(
            fqdn="dead.com",
            url="https://dead.com/",
            status=CaptureStatus.DNS_ERROR,
            captured_at=NOW,
            duration_ms=80,
            error="getaddrinfo ENOTFOUND",
        )
    )

    with duckdb.connect(str(db), read_only=True) as con:
        rows = con.execute(
            "SELECT fqdn, status, signals, error FROM captures ORDER BY fqdn"
        ).fetchall()
    assert rows[0][1] == "dns_error" and rows[0][3] == "getaddrinfo ENOTFOUND"
    assert json.loads(rows[1][2])["has_password_input"] is True
