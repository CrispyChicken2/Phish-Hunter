"""The VLM arm: measured only where the model could actually see the page."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.config import load_settings
from lookalike_hunter.eval.arms import ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM
from lookalike_hunter.eval.runner import load_captures, run_evaluation
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def scorer() -> Scorer:
    s = load_settings(ROOT / "configs" / "default.yaml")
    return Scorer(s.brands, s.scoring, VariantIndex.from_brands(s.brands, s.variants.swap_tlds))


def dataset_file(tmp_path: Path, rows: list[tuple[str, str]]) -> Path:
    path = tmp_path / "d.jsonl"
    path.write_text(
        "\n".join(
            f'{{"fqdn": "{fqdn}", "expected": "{label}", "source": "t", '
            f'"labelled_at": "2026-09-27"}}'
            for fqdn, label in rows
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def store_with(tmp_path: Path, captures: list[tuple[str, CaptureStatus, str | None]]) -> MatchStore:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    for index, (fqdn, status, verdict_label) in enumerate(captures):
        store.save_capture(
            CaptureResult(
                fqdn=fqdn,
                url=f"https://{fqdn}/",
                status=status,
                captured_at=NOW,
                duration_ms=100,
                screenshot_path=Path(f"{fqdn}/shot.png") if status is CaptureStatus.OK else None,
            )
        )
        if verdict_label is not None:
            store.save_verdict(
                capture_id=index + 1,
                fqdn=fqdn,
                backend="stub",
                model=None,
                verdict=Verdict(label=Label(verdict_label), confidence=0.9, evidence="x"),
                classified_at=NOW,
            )
    return store


def test_unreachable_sites_are_excluded_not_counted_wrong(tmp_path: Path, scorer: Scorer) -> None:
    """A phishing domain taken down before capture must not punish either arm.

    The Scorer still judges it (the name is all it needs); the vision model cannot,
    so it is excluded and counted.
    """
    dataset = dataset_file(
        tmp_path,
        [("paypa1-secure-login.com", "phishing"), ("xn--pypal-4ve.com", "phishing")],
    )
    store = store_with(
        tmp_path,
        [
            ("paypa1-secure-login.com", CaptureStatus.OK, "phishing"),
            ("xn--pypal-4ve.com", CaptureStatus.DNS_ERROR, None),  # taken down
        ],
    )

    report = run_evaluation(
        dataset,
        scorer,
        0.7,
        arms=(ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM),
        db_path=store.db_path,
    )

    scoring = report.arms[ARM_SCORING_ONLY]
    vlm = report.arms[ARM_SCORING_PLUS_VLM]

    assert scoring.evaluated == 2 and scoring.excluded == 0  # names need no page
    assert vlm.evaluated == 1 and vlm.excluded == 1
    assert vlm.excluded_sites == ["xn--pypal-4ve.com"]
    assert vlm.metrics.accuracy == 1.0  # judged only on what it could see


def test_vlm_verdict_beats_the_name_for_a_parked_site(tmp_path: Path, scorer: Scorer) -> None:
    """The whole point of the vision arm: a lookalike name serving a parking page."""
    dataset = dataset_file(tmp_path, [("lcloud-verify.live", "parked")])
    store = store_with(tmp_path, [("lcloud-verify.live", CaptureStatus.OK, "parked")])

    report = run_evaluation(
        dataset, scorer, 0.7, arms=(ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM), db_path=store.db_path
    )

    assert report.arms[ARM_SCORING_ONLY].mistakes  # the name says phishing
    assert not report.arms[ARM_SCORING_PLUS_VLM].mistakes  # the page says parked


def test_sites_below_threshold_need_no_verdict(tmp_path: Path, scorer: Scorer) -> None:
    """Production never classifies what it never alerted on, so nor does evaluation."""
    dataset = dataset_file(tmp_path, [("quiet-bakery-fixture.com", "legitimate")])
    store = store_with(tmp_path, [("quiet-bakery-fixture.com", CaptureStatus.OK, None)])

    vlm = run_evaluation(
        dataset, scorer, 0.7, arms=(ARM_SCORING_PLUS_VLM,), db_path=store.db_path
    ).arms[ARM_SCORING_PLUS_VLM]

    assert vlm.evaluated == 1 and vlm.excluded == 0
    assert vlm.predictions[0].predicted == "legitimate"


def test_alerted_but_unclassified_is_excluded(tmp_path: Path, scorer: Scorer) -> None:
    """Captured and alerted but never classified: excluded, and visibly so."""
    dataset = dataset_file(tmp_path, [("paypa1-secure-login.com", "phishing")])
    store = store_with(tmp_path, [("paypa1-secure-login.com", CaptureStatus.OK, None)])

    vlm = run_evaluation(
        dataset, scorer, 0.7, arms=(ARM_SCORING_PLUS_VLM,), db_path=store.db_path
    ).arms[ARM_SCORING_PLUS_VLM]

    assert vlm.evaluated == 0
    assert vlm.excluded_sites == ["paypa1-secure-login.com"]


def test_latest_capture_wins(tmp_path: Path, scorer: Scorer) -> None:
    """A site re-captured after a takedown is judged on what we last saw."""
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    for status in (CaptureStatus.OK, CaptureStatus.DNS_ERROR):
        store.save_capture(
            CaptureResult("a.com", "https://a.com/", status, NOW, 10, screenshot_path=Path("s.png"))
        )

    captures = load_captures(store.db_path, ["a.com"])

    assert captures["a.com"].status == "dns_error"
    assert not captures["a.com"].reachable


def test_vlm_arm_requires_a_database(tmp_path: Path, scorer: Scorer) -> None:
    dataset = dataset_file(tmp_path, [("a.com", "parked")])

    with pytest.raises(ValueError, match="needs a database"):
        run_evaluation(dataset, scorer, 0.7, arms=(ARM_SCORING_PLUS_VLM,))


def test_report_states_each_arm_denominator(tmp_path: Path, scorer: Scorer) -> None:
    dataset = dataset_file(
        tmp_path, [("paypa1-secure-login.com", "phishing"), ("xn--pypal-4ve.com", "phishing")]
    )
    store = store_with(
        tmp_path,
        [
            ("paypa1-secure-login.com", CaptureStatus.OK, "phishing"),
            ("xn--pypal-4ve.com", CaptureStatus.CONNECTION_ERROR, None),
        ],
    )

    report = run_evaluation(
        dataset, scorer, 0.7, arms=(ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM), db_path=store.db_path
    )
    markdown = report.to_markdown()

    assert "Judged 2 site(s); 0 excluded" in markdown
    assert "Judged 1 site(s); 1 excluded (no usable capture)" in markdown


def test_unknown_labels_are_excluded_from_metrics(tmp_path: Path, scorer: Scorer) -> None:
    """A Cloudflare challenge is not a class; it is an absence of ground truth."""
    dataset = dataset_file(
        tmp_path,
        [("paypa1-secure-login.com", "phishing"), ("macrosoft.lt", "unknown")],
    )
    store = store_with(tmp_path, [("paypa1-secure-login.com", CaptureStatus.OK, "phishing")])

    report = run_evaluation(dataset, scorer, 0.7, arms=(ARM_SCORING_ONLY,), db_path=store.db_path)

    assert report.dataset_size == 1  # only the judgeable site
    assert report.unjudgeable == 1
    assert "unknown" not in report.arms[ARM_SCORING_ONLY].metrics.per_class
    assert "excluded as unknown" in report.to_markdown()
