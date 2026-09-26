"""Run the labelled dataset through the detection arms and report what happened.

This is the seam the whole evaluation hangs off: given a dataset and the pieces of
the pipeline, produce a report. It performs no capture and no network access, so the
same inputs give the same numbers today and in six months.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from lookalike_hunter.classify.schema import Label
from lookalike_hunter.eval.dataset import LabelledSite, load_dataset
from lookalike_hunter.eval.metrics import compute_metrics
from lookalike_hunter.eval.report import (
    SCORING_ONLY_CAVEAT,
    ArmResult,
    EvaluationReport,
    Prediction,
)
from lookalike_hunter.logging import get_logger
from lookalike_hunter.scoring.scorer import Scorer

log = get_logger(__name__)

ARM_SCORING_ONLY = "scoring_only"


def _score_site(scorer: Scorer, site: LabelledSite) -> tuple[float, str | None]:
    """Best score for a site and the Brand that produced it.

    The certificate issuer is not passed: a dataset records hostnames, not
    certificates, so the free-DV issuer bonus is unavailable here. Both arms are
    scored the same way, so the comparison stays fair.
    """
    matches = scorer.score(site.fqdn)
    if not matches:
        return 0.0, None
    best = max(matches, key=lambda m: m.score)
    return best.score, best.brand


def _scoring_only_arm(
    sites: Sequence[LabelledSite], scorer: Scorer, alert_threshold: float
) -> ArmResult:
    predictions: list[Prediction] = []
    for site in sites:
        score, brand = _score_site(scorer, site)
        predicted = Label.PHISHING if score >= alert_threshold else Label.LEGITIMATE
        predictions.append(
            Prediction(
                fqdn=site.fqdn,
                expected=str(site.expected),
                predicted=str(predicted),
                score=score,
                brand=brand or site.brand,
                note=site.note,
            )
        )
    metrics = compute_metrics([(p.expected, p.predicted) for p in predictions])
    return ArmResult(
        name=ARM_SCORING_ONLY,
        metrics=metrics,
        predictions=predictions,
        caveat=SCORING_ONLY_CAVEAT,
    )


def run_evaluation(
    dataset_path: Path,
    scorer: Scorer,
    alert_threshold: float,
    arms: Sequence[str] = (ARM_SCORING_ONLY,),
) -> EvaluationReport:
    """Evaluate the requested arms over a labelled dataset."""
    sites = load_dataset(dataset_path)
    log.info("eval.start", dataset=str(dataset_path), sites=len(sites), arms=list(arms))

    results: dict[str, ArmResult] = {}
    for arm in arms:
        if arm == ARM_SCORING_ONLY:
            results[arm] = _scoring_only_arm(sites, scorer, alert_threshold)
        else:
            raise ValueError(f"unknown evaluation arm: {arm}")
        metrics = results[arm].metrics
        log.info(
            "eval.arm_done",
            arm=arm,
            accuracy=metrics.accuracy,
            macro_f1=metrics.macro_f1,
            mistakes=len(results[arm].mistakes),
        )

    return EvaluationReport(
        dataset_path=str(dataset_path),
        dataset_size=len(sites),
        generated_at=datetime.now(UTC),
        alert_threshold=alert_threshold,
        arms=results,
    )
