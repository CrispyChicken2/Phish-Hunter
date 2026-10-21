"""Rescoring stored Matches after the scoring configuration changes."""

from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from lookalike_hunter.cli import main
from lookalike_hunter.config import Settings, load_settings
from lookalike_hunter.ingest.parse import Certificate
from lookalike_hunter.ingest.rescore import rescore
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex

ROOT = Path(__file__).parents[1]
DEFAULT = ROOT / "configs" / "default.yaml"
NOW = datetime(2026, 10, 21, 9, 0, tzinfo=UTC)
HOSTS = ("paypa1-secure-login.com", "secure-paypal-account.net")


def scorer_for(settings: Settings) -> Scorer:
    index = VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds)
    return Scorer(settings.brands, settings.scoring, index)


def ingested(tmp_path: Path, settings: Settings, issuer: str = "Let's Encrypt") -> MatchStore:
    """Store HOSTS the way ingestion does, scored with ``settings``."""
    store = MatchStore(tmp_path / "t.duckdb", settings.scoring.alert_threshold)
    scorer = scorer_for(settings)
    rows = []
    for i, host in enumerate(HOSTS):
        certificate = Certificate(f"{i:064d}", NOW, issuer, NOW, NOW, "log", (host,))
        rows += [(certificate, match) for match in scorer.score(host, issuer)]
    assert store.write(rows) >= len(HOSTS)
    return store


def stored(store: MatchStore) -> dict[tuple[str, str], tuple[float, bool]]:
    with duckdb.connect(str(store.db_path), read_only=True) as con:
        rows = con.execute("SELECT fqdn, brand, score, is_alert FROM matches").fetchall()
    return {(f, b): (s, a) for f, b, s, a in rows}


@pytest.fixture
def settings() -> Settings:
    return load_settings(DEFAULT)


def test_an_unchanged_configuration_changes_nothing(tmp_path: Path, settings: Settings) -> None:
    """The baseline: the issuer is read back, so free-DV bonuses are reproduced too."""
    store = ingested(tmp_path, settings)

    report = rescore(store.db_path, scorer_for(settings), settings.scoring.alert_threshold)

    assert report.checked == len(stored(store)) and report.changes == []


def test_a_dry_run_reports_without_writing(tmp_path: Path, settings: Settings) -> None:
    store = ingested(tmp_path, settings)
    before = stored(store)
    stricter = settings.scoring.model_copy(update={"alert_threshold": 0.99})

    report = rescore(store.db_path, scorer_for(settings), stricter.alert_threshold)

    assert report.no_longer_alerting and not report.applied
    assert stored(store) == before


def test_applying_brings_every_row_up_to_date_once(tmp_path: Path, settings: Settings) -> None:
    store = ingested(tmp_path, settings)
    weights = settings.scoring.weights.model_copy(update={"keyword_bonus": 0.0})
    changed = settings.model_copy(
        update={"scoring": settings.scoring.model_copy(update={"weights": weights})}
    )
    scorer = scorer_for(changed)

    report = rescore(store.db_path, scorer, 0.7, apply=True)

    assert report.changes and report.applied
    expected = {
        (m.fqdn, m.brand): m.score for host in HOSTS for m in scorer.score(host, "Let's Encrypt")
    }
    assert {key: score for key, (score, _) in stored(store).items()} == pytest.approx(expected)
    assert rescore(store.db_path, scorer, 0.7).changes == []  # idempotent


def test_a_row_now_below_the_storage_floor_is_kept_with_its_real_score(
    tmp_path: Path, settings: Settings
) -> None:
    """Deleting it would lose its first sighting and its link to captures."""
    store = ingested(tmp_path, settings)
    weights = settings.scoring.weights.model_copy(
        update={name: 0.0 for name in ("token_in_registered_label", "typo_similarity")}
    )
    weak = settings.model_copy(
        update={"scoring": settings.scoring.model_copy(update={"weights": weights})}
    )

    rescore(store.db_path, scorer_for(weak), 0.7, apply=True)

    after = stored(store)
    assert len(after) >= len(HOSTS)  # nothing deleted
    assert all(
        score < settings.scoring.store_floor and not alert for score, alert in after.values()
    )


def test_a_brand_no_longer_configured_scores_zero(tmp_path: Path, settings: Settings) -> None:
    store = ingested(tmp_path, settings)
    without_paypal = settings.model_copy(
        update={"brands": [b for b in settings.brands if b.name != "paypal"]}
    )

    rescore(store.db_path, scorer_for(without_paypal), 0.7, apply=True)

    paypal_rows = {k: v for k, v in stored(store).items() if k[1] == "paypal"}
    assert paypal_rows and set(paypal_rows.values()) == {(0.0, False)}


def test_the_command_is_a_dry_run_unless_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = load_settings(DEFAULT)
    store = ingested(tmp_path, settings)
    before = stored(store)
    monkeypatch.setenv("LH_DB_PATH", str(store.db_path))
    monkeypatch.setenv("LH_SCORING__ALERT_THRESHOLD", "0.99")

    main(["--config", str(DEFAULT), "rescore"])
    assert stored(store) == before
    main(["--config", str(DEFAULT), "rescore", "--apply"])

    out = capsys.readouterr().out
    assert "stop being Alerts" in out and "no longer an Alert" in out
    assert "Dry run: nothing written" in out and "Applied." in out
    assert not any(alert for _, alert in stored(store).values())


def test_a_match_linked_to_another_sites_certificate_keeps_its_free_dv_flag(
    tmp_path: Path, settings: Settings
) -> None:
    """Seen on the instance: before the parse fix, Matches could point at another
    site's certificate, whose issuer then removed a free-DV bonus that was right."""
    store = MatchStore(tmp_path / "t.duckdb", settings.scoring.alert_threshold)
    host = HOSTS[0]
    (match,) = scorer_for(settings).score(host, "Let's Encrypt")
    elsewhere = Certificate("e" * 64, NOW, "Microsoft Corporation", NOW, NOW, "log", ("x.test",))
    store.write([(elsewhere, match)])

    report = rescore(store.db_path, scorer_for(settings), settings.scoring.alert_threshold)

    assert report.changes == []
