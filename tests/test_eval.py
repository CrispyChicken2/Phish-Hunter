"""Evaluation harness tests.

The fixture dataset is built so the confusion matrix is known, which lets the metric
arithmetic be asserted as literal values rather than recomputed by the test using the
same code it is meant to check.
"""

import json
from datetime import date
from pathlib import Path

import pytest

from lookalike_hunter.classify.schema import Label
from lookalike_hunter.config import load_settings
from lookalike_hunter.eval.arms import ARM_SCORING_ONLY
from lookalike_hunter.eval.dataset import DatasetError, load_dataset
from lookalike_hunter.eval.report import write_report
from lookalike_hunter.eval.runner import run_evaluation
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex

ROOT = Path(__file__).parents[1]
DATASET = ROOT / "tests" / "fixtures" / "eval_dataset.jsonl"


@pytest.fixture(scope="module")
def scorer() -> Scorer:
    s = load_settings(ROOT / "configs" / "default.yaml")
    return Scorer(s.brands, s.scoring, VariantIndex.from_brands(s.brands, s.variants.swap_tlds))


# --------------------------------------------------------------------------- dataset


def test_dataset_loads_with_provenance() -> None:
    sites = load_dataset(DATASET)

    assert len(sites) == 8
    first = sites[0]
    assert first.fqdn == "paypa1-secure-login.com"
    assert first.expected is Label.PHISHING
    assert first.source == "fixture"
    assert first.labelled_at == date(2026, 9, 27)


def test_comments_and_blank_lines_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "d.jsonl"
    path.write_text(
        '# a comment\n\n{"fqdn": "a.com", "expected": "parked", '
        '"source": "s", "labelled_at": "2026-01-01"}\n',
        encoding="utf-8",
    )
    assert len(load_dataset(path)) == 1


@pytest.mark.parametrize(
    ("line", "expected_message"),
    [
        ("{not json}", "not valid JSON"),
        ('{"fqdn": "a.com", "expected": "parked"}', "missing field"),
        (
            '{"fqdn": "a.com", "expected": "banana", "source": "s", "labelled_at": "2026-01-01"}',
            "unknown label",
        ),
        (
            '{"fqdn": "a.com", "expected": "parked", "source": "s", "labelled_at": "yesterday"}',
            "ISO date",
        ),
        ('["not", "an", "object"]', "expected a JSON object"),
    ],
)
def test_malformed_entry_names_the_line(tmp_path: Path, line: str, expected_message: str) -> None:
    path = tmp_path / "d.jsonl"
    path.write_text(f"# header\n{line}\n", encoding="utf-8")

    with pytest.raises(DatasetError) as excinfo:
        load_dataset(path)

    message = str(excinfo.value)
    assert expected_message in message
    assert ":2:" in message  # the offending line, not just "somewhere in the file"


def test_duplicate_sites_are_rejected(tmp_path: Path) -> None:
    entry = '{"fqdn": "a.com", "expected": "parked", "source": "s", "labelled_at": "2026-01-01"}'
    path = tmp_path / "d.jsonl"
    path.write_text(f"{entry}\n{entry}\n", encoding="utf-8")

    with pytest.raises(DatasetError, match="appears twice"):
        load_dataset(path)


def test_empty_dataset_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "d.jsonl"
    path.write_text("# only a comment\n", encoding="utf-8")
    with pytest.raises(DatasetError, match="empty"):
        load_dataset(path)


# ------------------------------------------------------------------------ evaluation


def test_scoring_only_arm_metrics(scorer: Scorer) -> None:
    """Expected confusion matrix for the fixture, at threshold 0.7:

    predicted phishing: paypa1-secure-login, xn--pypal-4ve, apple-verify-fixture,
                        paypal-login-fixture (legitimate), lcloud-verify (parked)
    predicted legitimate: generic-account-alert (phishing), quiet-bakery, hummelcloud

    phishing   : TP 3, FP 2, FN 1  -> precision 0.6,    recall 0.75,   F1 0.6667
    legitimate : TP 2, FP 1, FN 1  -> precision 0.6667, recall 0.6667, F1 0.6667
    parked     : TP 0, FP 0, FN 1  -> all zero (the arm cannot predict parked)
    accuracy   : 5/8 = 0.625
    """
    report = run_evaluation(DATASET, scorer, alert_threshold=0.7)
    arm = report.arms[ARM_SCORING_ONLY]
    m = arm.metrics

    assert m.total == 8
    assert m.correct == 5
    assert m.accuracy == 0.625

    assert m.per_class["phishing"].true_positives == 3
    assert m.per_class["phishing"].false_positives == 2
    assert m.per_class["phishing"].false_negatives == 1
    assert m.per_class["phishing"].precision == 0.6
    assert m.per_class["phishing"].recall == 0.75
    assert m.per_class["phishing"].f1 == 0.6667

    assert m.per_class["legitimate"].precision == 0.6667
    assert m.per_class["legitimate"].recall == 0.6667

    # The Scorer never predicts parked, so the class scores zero across the board.
    assert m.per_class["parked"].support == 1
    assert m.per_class["parked"].predicted == 0
    assert m.per_class["parked"].precision == 0.0
    assert m.per_class["parked"].f1 == 0.0

    assert m.macro_f1 == round((0.6667 + 0.6667 + 0.0) / 3, 4)


def test_confusion_matrix_rows_sum_to_support(scorer: Scorer) -> None:
    m = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY].metrics

    for label, row in m.confusion.items():
        assert sum(row.values()) == m.per_class[label].support


def test_mistakes_are_listed_with_scores(scorer: Scorer) -> None:
    arm = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY]

    mistakes = {p.fqdn: p for p in arm.mistakes}
    assert set(mistakes) == {
        "generic-account-alert.com",  # phishing missed entirely
        "paypal-login-fixture.com",  # legitimate flagged
        "lcloud-verify.live",  # parked flagged: the structural gap
    }
    assert mistakes["generic-account-alert.com"].score == 0.0
    assert mistakes["lcloud-verify.live"].score >= 0.7


def test_raising_the_threshold_changes_the_outcome(scorer: Scorer) -> None:
    """A metric that never moves would mean the harness ignores its inputs."""
    low = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY].metrics
    high = run_evaluation(DATASET, scorer, alert_threshold=0.95).arms[ARM_SCORING_ONLY].metrics

    assert high.per_class["phishing"].predicted < low.per_class["phishing"].predicted


def test_unknown_arm_is_rejected(scorer: Scorer) -> None:
    with pytest.raises(ValueError, match="unknown evaluation arm"):
        run_evaluation(DATASET, scorer, 0.7, arms=("telepathy",))


def test_report_records_its_conditions(scorer: Scorer) -> None:
    report = run_evaluation(DATASET, scorer, alert_threshold=0.7)

    assert report.dataset_size == 8
    assert report.alert_threshold == 0.7
    assert str(DATASET) in report.dataset_path
    assert report.generated_at.tzinfo is not None


# ---------------------------------------------------------------------------- report


def test_report_is_written_in_both_formats(tmp_path: Path, scorer: Scorer) -> None:
    report = run_evaluation(DATASET, scorer, alert_threshold=0.7)

    json_path, markdown_path = write_report(report, tmp_path)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["dataset_size"] == 8
    assert payload["arms"][ARM_SCORING_ONLY]["metrics"]["accuracy"] == 0.625

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# Evaluation report" in markdown
    assert "Confusion matrix" in markdown
    assert "cannot predict parked" in markdown  # the caveat travels with the numbers
    assert "paypal-login-fixture.com" in markdown  # mistakes are visible


# ----------------------------------------------------------------------- sweep


def test_threshold_sweep_is_reported(scorer: Scorer) -> None:
    arm = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY]

    assert arm.sweep is not None
    thresholds = [p.threshold for p in arm.sweep.points]
    assert thresholds == sorted(thresholds)
    configured = [p for p in arm.sweep.points if p.is_configured]
    assert len(configured) == 1 and configured[0].threshold == 0.7


def test_sweep_shows_the_precision_recall_trade(scorer: Scorer) -> None:
    """Raising the threshold must shrink the queue and never raise recall."""
    sweep = run_evaluation(DATASET, scorer, 0.7).arms[ARM_SCORING_ONLY].sweep
    assert sweep is not None
    points = {p.threshold: p for p in sweep.points}

    assert points[0.4].alerts >= points[0.9].alerts
    assert points[0.4].recall >= points[0.9].recall


def test_sweep_matches_the_arm_at_the_configured_threshold(scorer: Scorer) -> None:
    """The sweep and the headline metrics must agree where they overlap."""
    arm = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY]
    assert arm.sweep is not None
    configured = next(p for p in arm.sweep.points if p.is_configured)

    assert configured.precision == arm.metrics.per_class["phishing"].precision
    assert configured.recall == arm.metrics.per_class["phishing"].recall


# ------------------------------------------------------------------ per brand


def test_per_brand_breakdown(scorer: Scorer) -> None:
    arm = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY]

    assert "paypal" in arm.per_brand
    assert sum(m.total for m in arm.per_brand.values()) == arm.metrics.total


def test_costly_mistakes_are_separated(scorer: Scorer) -> None:
    """Phishing judged harmless is the expensive error and must stand out."""
    arm = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY]

    costly = {p.fqdn for p in arm.costly_mistakes}
    assert costly == {"generic-account-alert.com"}  # a real attack let through
    assert len(arm.mistakes) > len(arm.costly_mistakes)


def test_report_renders_sweep_and_brands(tmp_path: Path, scorer: Scorer) -> None:
    report = run_evaluation(DATASET, scorer, alert_threshold=0.7)

    markdown = report.to_markdown()

    assert "Alert threshold sweep" in markdown
    assert "Per brand" in markdown
    assert "configured" in markdown
    assert "Phishing judged harmless" in markdown


def test_per_source_split(scorer: Scorer) -> None:
    """CT alerts and feed URLs are different populations and must not be averaged."""
    arm = run_evaluation(DATASET, scorer, alert_threshold=0.7).arms[ARM_SCORING_ONLY]

    assert "fixture" in arm.per_source
    assert sum(m.total for m in arm.per_source.values()) == arm.metrics.total


def test_report_renders_the_source_split(scorer: Scorer) -> None:
    markdown = run_evaluation(DATASET, scorer, alert_threshold=0.7).to_markdown()

    assert "Per source" in markdown
    assert "never shows a page hosted on github.io" in markdown
