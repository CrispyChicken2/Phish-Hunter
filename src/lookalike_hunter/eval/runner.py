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
    db_path: Path, fqdns: Sequence[str], backend: str | None = None
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
            SELECT c.fqdn, c.status, c.screenshot_path,
                   (SELECT v.label FROM verdicts v
                     WHERE v.capture_id = c.capture_id
                       AND (? IS NULL OR v.backend = ?)
                       AND v.label <> 'error'
                     ORDER BY v.verdict_id DESC LIMIT 1)
            FROM captures c JOIN latest USING (capture_id)
            """,
            [list(fqdns), backend, backend],
        ).fetchall()
    return {
        fqdn: StoredCapture(
            fqdn=fqdn,
            status=status,
            verdict_label=verdict,
            screenshot_path=Path(shot) if shot else None,
        )
        for fqdn, status, shot, verdict in rows
    }


def run_evaluation(
    dataset_path: Path,
    scorer: Scorer,
    alert_threshold: float,
    arms: Sequence[str] = (ARM_SCORING_ONLY,),
    db_path: Path | None = None,
    backend: str | None = None,
) -> EvaluationReport:
    """Evaluate the requested arms over a labelled dataset."""
    unknown = [arm for arm in arms if arm not in KNOWN_ARMS]
    if unknown:
        raise ValueError(f"unknown evaluation arm: {unknown[0]}")

    sites = load_dataset(dataset_path)
    log.info("eval.start", dataset=str(dataset_path), sites=len(sites), arms=list(arms))

    captures: dict[str, StoredCapture] = {}
    if ARM_SCORING_PLUS_VLM in arms:
        if db_path is None:
            raise ValueError(f"{ARM_SCORING_PLUS_VLM} needs a database of stored captures")
        captures = load_captures(db_path, [s.fqdn for s in sites], backend)

    results: dict[str, ArmResult] = {}
    for arm in arms:
        if arm == ARM_SCORING_ONLY:
            results[arm] = scoring_only_arm(sites, scorer, alert_threshold)
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
        generated_at=datetime.now(UTC),
        alert_threshold=alert_threshold,
        arms=results,
    )
