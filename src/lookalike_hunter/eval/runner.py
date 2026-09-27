"""Run the labelled dataset through the detection arms and report what happened.

This is the seam the whole evaluation hangs off: given a dataset and the pieces of
the pipeline, produce a report. It performs no capture and no network access, so
the same inputs give the same numbers today and in six months. Captures and
Verdicts are read from what the capture and classify commands already stored.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from lookalike_hunter.classify.schema import Label
from lookalike_hunter.eval.arms import (
    ARM_SCORING_ONLY,
    ARM_SCORING_PLUS_VLM,
    StoredCapture,
    scoring_only_arm,
    scoring_plus_vlm_arm,
)
from lookalike_hunter.eval.dataset import load_dataset
from lookalike_hunter.eval.report import ArmResult, EvaluationReport
from lookalike_hunter.ingest.store import connect_with_retry
from lookalike_hunter.logging import get_logger
from lookalike_hunter.scoring.scorer import Scorer

log = get_logger(__name__)

KNOWN_ARMS = (ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM)


def load_captures(
    db_path: Path,
    fqdns: Sequence[str],
    backend: str | None = None,
    model: str | None = None,
) -> dict[str, StoredCapture]:
    """The most recent Capture per hostname, with its Verdict when one exists.

    Latest wins: a site re-captured after a takedown should be judged on what we
    last saw, not on the first attempt.
    """
    if not db_path.exists() or not fqdns:
        return {}
    with connect_with_retry(db_path, read_only=True) as con:
        rows = con.execute(
            """
            WITH latest AS (
                SELECT fqdn, max(capture_id) AS capture_id
                FROM captures WHERE fqdn IN (SELECT unnest(?)) GROUP BY fqdn
            )
            SELECT c.fqdn, c.status, c.screenshot_path, c.duration_ms,
                   (SELECT v.label FROM verdicts v
                     WHERE v.capture_id = c.capture_id
                       AND (? IS NULL OR v.backend = ?)
                       AND (? IS NULL OR v.model = ?)
                       AND v.label <> 'error'
                     ORDER BY v.verdict_id DESC LIMIT 1),
                   (SELECT v.brand_impersonated FROM verdicts v
                     WHERE v.capture_id = c.capture_id
                       AND (? IS NULL OR v.backend = ?)
                       AND (? IS NULL OR v.model = ?)
                       AND v.label <> 'error'
                     ORDER BY v.verdict_id DESC LIMIT 1),
                   (SELECT coalesce(v.latency_ms, 0) FROM verdicts v
                     WHERE v.capture_id = c.capture_id AND v.label <> 'error'
                       AND (? IS NULL OR v.backend = ?) AND (? IS NULL OR v.model = ?)
                     ORDER BY v.verdict_id DESC LIMIT 1),
                   (SELECT coalesce(v.prompt_tokens, 0) + coalesce(v.completion_tokens, 0)
                      FROM verdicts v
                     WHERE v.capture_id = c.capture_id AND v.label <> 'error'
                       AND (? IS NULL OR v.backend = ?) AND (? IS NULL OR v.model = ?)
                     ORDER BY v.verdict_id DESC LIMIT 1),
                   (SELECT coalesce(v.cost_usd, 0) FROM verdicts v
                     WHERE v.capture_id = c.capture_id AND v.label <> 'error'
                       AND (? IS NULL OR v.backend = ?) AND (? IS NULL OR v.model = ?)
                     ORDER BY v.verdict_id DESC LIMIT 1)
            FROM captures c JOIN latest USING (capture_id)
            """,
            [
                list(fqdns),
                backend,
                backend,
                model,
                model,
                backend,
                backend,
                model,
                model,
                backend,
                backend,
                model,
                model,
                backend,
                backend,
                model,
                model,
                backend,
                backend,
                model,
                model,
            ],
        ).fetchall()
    return {
        row[0]: StoredCapture(
            fqdn=row[0],
            status=row[1],
            screenshot_path=Path(row[2]) if row[2] else None,
            capture_ms=int(row[3] or 0),
            verdict_label=row[4],
            verdict_brand=row[5],
            classify_ms=int(row[6] or 0),
            tokens=int(row[7] or 0),
            cost_usd=float(row[8] or 0.0),
        )
        for row in rows
    }


def run_evaluation(
    dataset_path: Path,
    scorer: Scorer,
    alert_threshold: float,
    arms: Sequence[str] = (ARM_SCORING_ONLY,),
    db_path: Path | None = None,
    backend: str | None = None,
    model: str | None = None,
) -> EvaluationReport:
    """Evaluate the requested arms over a labelled dataset."""
    unknown = [arm for arm in arms if arm not in KNOWN_ARMS]
    if unknown:
        raise ValueError(f"unknown evaluation arm: {unknown[0]}")

    all_sites = load_dataset(dataset_path)
    # A site labelled unknown carries no ground truth: a Cloudflare challenge or an
    # empty frame tells us nothing about either arm. Counting it as a class of its
    # own would drag every macro average toward zero for no reason, so it is
    # excluded and reported rather than quietly folded in.
    sites = [s for s in all_sites if s.expected is not Label.UNKNOWN]
    unjudgeable = len(all_sites) - len(sites)
    log.info(
        "eval.start",
        dataset=str(dataset_path),
        sites=len(sites),
        unjudgeable=unjudgeable,
        arms=list(arms),
    )

    captures: dict[str, StoredCapture] = {}
    if ARM_SCORING_PLUS_VLM in arms and db_path is None:
        raise ValueError(f"{ARM_SCORING_PLUS_VLM} needs a database of stored captures")
    if db_path is not None:
        # Screenshots make every arm's mistakes reviewable, not only the VLM's.
        captures = load_captures(db_path, [s.fqdn for s in sites], backend, model)

    results: dict[str, ArmResult] = {}
    for arm in arms:
        if arm == ARM_SCORING_ONLY:
            results[arm] = scoring_only_arm(sites, scorer, alert_threshold, captures)
        else:
            results[arm] = scoring_plus_vlm_arm(sites, scorer, alert_threshold, captures)
        metrics = results[arm].metrics
        log.info(
            "eval.arm_done",
            arm=arm,
            judged=results[arm].evaluated,
            excluded=results[arm].excluded,
            accuracy=metrics.accuracy,
            macro_f1=metrics.macro_f1,
            mistakes=len(results[arm].mistakes),
        )

    return EvaluationReport(
        dataset_path=str(dataset_path),
        dataset_size=len(sites),
        unjudgeable=unjudgeable,
        generated_at=datetime.now(UTC),
        alert_threshold=alert_threshold,
        arms=results,
    )
