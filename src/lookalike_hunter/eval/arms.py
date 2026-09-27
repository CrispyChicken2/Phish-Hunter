"""The two detection arms, scored over the same dataset.

They do not see the same evidence, and pretending otherwise would corrupt both
numbers. The Scorer judges a name, so a site taken down before we visited is still
fair game: flagging it was correct. The vision model judges a page, so it can only
be measured where a Capture succeeded. Each arm therefore reports its own
denominator, and the sites excluded from an arm are counted rather than dropped.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from lookalike_hunter.classify.schema import Label
from lookalike_hunter.eval.dataset import LabelledSite
from lookalike_hunter.eval.metrics import Metrics, compute_metrics
from lookalike_hunter.eval.report import ArmResult, Prediction
from lookalike_hunter.eval.sweep import sweep_thresholds
from lookalike_hunter.scoring.scorer import Scorer

ARM_SCORING_ONLY = "scoring_only"
ARM_SCORING_PLUS_VLM = "scoring_plus_vlm"

SCORING_ONLY_CAVEAT = (
    "Judged on names alone, over every labelled site including those since taken "
    "down. Predicts phishing at or above the alert threshold and legitimate below "
    "it; it cannot predict parked, which needs the page, so parked sites count "
    "against its precision."
)

VLM_CAVEAT = (
    "Judged on the screenshot, so it is measured only where a capture succeeded. "
    "Sites that were gone before we could visit are excluded and counted "
    "separately: scoring them here would measure takedown speed, not the model."
)


@dataclass(frozen=True, slots=True)
class StoredCapture:
    """What the evaluation needs to know about a Capture, already on disk."""

    fqdn: str
    status: str
    verdict_label: str | None = None
    screenshot_path: Path | None = None
    verdict_brand: str | None = None
    capture_ms: int = 0
    classify_ms: int = 0
    tokens: int = 0
    cost_usd: float = 0.0

    @property
    def reachable(self) -> bool:
        return self.status == "ok"


def score_of(scorer: Scorer, fqdn: str) -> tuple[float, str | None]:
    """Best score for a hostname and the Brand that produced it.

    No certificate issuer is passed: a dataset records hostnames, not certificates,
    so the free-DV bonus is unavailable. Both arms are scored the same way.
    """
    matches = scorer.score(fqdn)
    if not matches:
        return 0.0, None
    best = max(matches, key=lambda m: m.score)
    return best.score, best.brand


@dataclass(frozen=True, slots=True)
class ArmCost:
    """What an arm spent to reach its verdicts.

    Accuracy alone cannot decide whether the vision step earns its place; the
    comparison needs the price next to the benefit.
    """

    capture_ms: int = 0
    classify_ms: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    sites: int = 0

    @property
    def ms_per_site(self) -> float:
        return round((self.capture_ms + self.classify_ms) / self.sites, 1) if self.sites else 0.0

    @property
    def usd_per_1000_sites(self) -> float:
        return round(self.cost_usd / self.sites * 1000, 4) if self.sites else 0.0


def cost_of(fqdns: Sequence[str], captures: dict[str, StoredCapture]) -> ArmCost:
    """Sum what the pipeline actually spent on these sites."""
    used = [captures[f] for f in fqdns if f in captures]
    return ArmCost(
        capture_ms=sum(c.capture_ms for c in used),
        classify_ms=sum(c.classify_ms for c in used),
        tokens=sum(c.tokens for c in used),
        cost_usd=round(sum(c.cost_usd for c in used), 6),
        sites=len(fqdns),
    )


def per_brand_metrics(predictions: Sequence[Prediction]) -> dict[str, Metrics]:
    """Metrics split by Brand, which is where short-token weakness would show."""
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for prediction in predictions:
        grouped[prediction.brand or "(none)"].append((prediction.expected, prediction.predicted))
    return {brand: compute_metrics(pairs) for brand, pairs in sorted(grouped.items())}


def scoring_only_arm(
    sites: Sequence[LabelledSite],
    scorer: Scorer,
    alert_threshold: float,
    captures: dict[str, StoredCapture] | None = None,
) -> ArmResult:
    captures = captures or {}
    predictions = []
    for site in sites:
        score, brand = score_of(scorer, site.fqdn)
        predicted = Label.PHISHING if score >= alert_threshold else Label.LEGITIMATE
        capture = captures.get(site.fqdn)
        predictions.append(
            Prediction(
                fqdn=site.fqdn,
                expected=str(site.expected),
                predicted=str(predicted),
                score=score,
                brand=brand or site.brand,
                note=site.note,
                screenshot=str(capture.screenshot_path) if capture else None,
            )
        )
    return ArmResult(
        name=ARM_SCORING_ONLY,
        metrics=compute_metrics([(p.expected, p.predicted) for p in predictions]),
        predictions=predictions,
        caveat=SCORING_ONLY_CAVEAT,
        evaluated=len(predictions),
        excluded=0,
        per_brand=per_brand_metrics(predictions),
        # The sweep belongs to the arm whose behaviour the threshold governs.
        sweep=sweep_thresholds([(p.expected, p.score) for p in predictions], alert_threshold),
        # Names only: no page fetched, no model called, nothing billed.
        cost=ArmCost(sites=len(predictions)),
    )


def scoring_plus_vlm_arm(
    sites: Sequence[LabelledSite],
    scorer: Scorer,
    alert_threshold: float,
    captures: dict[str, StoredCapture],
) -> ArmResult:
    """Score the full pipeline: alert, then look at the page.

    Sites below the threshold predict legitimate without a model call, exactly as
    production behaves; there is no point paying for a verdict we would not request.
    """
    predictions = []
    excluded: list[str] = []
    for site in sites:
        capture = captures.get(site.fqdn)
        if capture is None or not capture.reachable:
            excluded.append(site.fqdn)
            continue

        score, brand = score_of(scorer, site.fqdn)
        if score < alert_threshold:
            predicted = str(Label.LEGITIMATE)
        elif capture.verdict_label is None:
            excluded.append(site.fqdn)  # alerted, captured, but never classified
            continue
        else:
            predicted = capture.verdict_label

        predictions.append(
            Prediction(
                fqdn=site.fqdn,
                expected=str(site.expected),
                predicted=predicted,
                score=score,
                brand=brand or site.brand,
                note=site.note,
                screenshot=str(capture.screenshot_path) if capture.screenshot_path else None,
                verdict_brand=capture.verdict_brand,
            )
        )

    return ArmResult(
        name=ARM_SCORING_PLUS_VLM,
        metrics=compute_metrics([(p.expected, p.predicted) for p in predictions]),
        predictions=predictions,
        caveat=VLM_CAVEAT,
        evaluated=len(predictions),
        excluded=len(excluded),
        excluded_sites=excluded,
        per_brand=per_brand_metrics(predictions),
        cost=cost_of([p.fqdn for p in predictions], captures),
    )
