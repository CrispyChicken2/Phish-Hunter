"""The evaluation result: what was measured, on what, and under which settings.

Written as JSON so a machine can diff two runs, and as Markdown so a human can read
one. Both carry the provenance (dataset, configuration, timestamp), because a metric
without its conditions cannot be compared with anything.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from lookalike_hunter.eval.metrics import Metrics
from lookalike_hunter.eval.sweep import ThresholdSweep

if TYPE_CHECKING:  # avoids a cycle: arms imports report
    from lookalike_hunter.eval.arms import ArmCost


@dataclass(frozen=True, slots=True)
class Prediction:
    fqdn: str
    expected: str
    predicted: str
    score: float
    brand: str | None = None
    note: str | None = None
    screenshot: str | None = None
    source: str | None = None
    # A Verdict naming an impersonated Brand while calling the page something other
    # than phishing: an internal contradiction seen in live output, counted here.
    verdict_brand: str | None = None

    @property
    def is_costly(self) -> bool:
        """Phishing judged harmless: the error that lets an attack through."""
        return self.expected == "phishing" and self.predicted != "phishing"


@dataclass(frozen=True, slots=True)
class ArmResult:
    name: str
    metrics: Metrics
    predictions: list[Prediction] = field(default_factory=list)
    caveat: str | None = None
    # Arms see different evidence, so each states how many sites it could judge.
    evaluated: int = 0
    excluded: int = 0
    excluded_sites: list[str] = field(default_factory=list)
    per_brand: dict[str, Metrics] = field(default_factory=dict)
    # CT alerts and feed URLs are different populations; averaging them into one
    # number hides that the pipeline is blind to one of them by construction.
    per_source: dict[str, Metrics] = field(default_factory=dict)
    sweep: ThresholdSweep | None = None
    cost: ArmCost | None = None

    @property
    def mistakes(self) -> list[Prediction]:
        return [p for p in self.predictions if p.expected != p.predicted]

    @property
    def costly_mistakes(self) -> list[Prediction]:
        return [p for p in self.mistakes if p.is_costly]

    @property
    def contradictory_verdicts(self) -> list[Prediction]:
        return [p for p in self.predictions if p.verdict_brand and p.predicted != "phishing"]


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    dataset_path: str
    dataset_size: int
    generated_at: datetime
    alert_threshold: float
    unjudgeable: int = 0
    arms: dict[str, ArmResult] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str, sort_keys=True)

    def to_markdown(self) -> str:
        lines = [
            "# Evaluation report",
            "",
            f"- Dataset: `{self.dataset_path}` ({self.dataset_size} judgeable sites"
            + (f", {self.unjudgeable} excluded as unknown)" if self.unjudgeable else ")"),
            f"- Generated: {self.generated_at:%Y-%m-%d %H:%M:%S} UTC",
            f"- Alert threshold: {self.alert_threshold}",
            "",
        ]
        for arm in self.arms.values():
            lines += [f"## Arm: {arm.name}", ""]
            if arm.caveat:
                lines += [f"> {arm.caveat}", ""]
            m = arm.metrics
            lines += [
                f"Accuracy: **{m.accuracy:.2%}** ({m.correct}/{m.total}) · "
                f"macro F1: **{m.macro_f1:.4f}**",
                "",
                f"Judged {arm.evaluated} site(s); {arm.excluded} excluded"
                + (" (no usable capture)." if arm.excluded else "."),
                "",
                "| Class | Support | Predicted | TP | FP | FN | Precision | Recall | F1 |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
            for c in m.per_class.values():
                lines.append(
                    f"| {c.label} | {c.support} | {c.predicted} | {c.true_positives} | "
                    f"{c.false_positives} | {c.false_negatives} | {c.precision:.4f} | "
                    f"{c.recall:.4f} | {c.f1:.4f} |"
                )
            lines += ["", "### Confusion matrix (rows = expected, columns = predicted)", ""]
            labels = sorted(m.confusion)
            lines += [
                "| expected \\ predicted | " + " | ".join(labels) + " |",
                "|---" * (len(labels) + 1) + "|",
            ]
            for expected in labels:
                row = " | ".join(str(m.confusion[expected][p]) for p in labels)
                lines.append(f"| **{expected}** | {row} |")

            if arm.cost is not None:
                spend = arm.cost
                lines += [
                    "",
                    "### Cost",
                    "",
                    f"- Capture: {spend.capture_ms / 1000:.1f}s total",
                    f"- Classify: {spend.classify_ms / 1000:.1f}s total, {spend.tokens} tokens",
                    f"- Per site: {spend.ms_per_site:.0f} ms, "
                    f"${spend.usd_per_1000_sites:.4f} per 1000 sites",
                ]

            if arm.per_source:
                lines += [
                    "",
                    "### Per source",
                    "",
                    "Different populations: Certificate Transparency never shows a page "
                    "hosted on github.io or S3, so feed entries are largely invisible to "
                    "name-based scoring by construction.",
                    "",
                    "| Source | Sites | Accuracy | Macro F1 |",
                    "|---|---:|---:|---:|",
                ]
                for source, sm in sorted(arm.per_source.items()):
                    lines.append(
                        f"| {source} | {sm.total} | {sm.accuracy:.2%} | {sm.macro_f1:.4f} |"
                    )

            if arm.per_brand:
                lines += [
                    "",
                    "### Per brand",
                    "",
                    "| Brand | Sites | Accuracy | Macro F1 |",
                    "|---|---:|---:|---:|",
                ]
                for brand, bm in sorted(arm.per_brand.items()):
                    lines.append(
                        f"| {brand} | {bm.total} | {bm.accuracy:.2%} | {bm.macro_f1:.4f} |"
                    )

            costly = arm.costly_mistakes
            lines += ["", f"### Mistakes ({len(arm.mistakes)}, of which {len(costly)} costly)", ""]
            if costly:
                lines += ["**Phishing judged harmless** (an attack would have gone through):", ""]
                lines += _mistake_table(costly)
            others = [p for p in arm.mistakes if not p.is_costly]
            if others:
                lines += ["", "**Other mistakes** (noise in the queue):", ""]
                lines += _mistake_table(others)
            if not arm.mistakes:
                lines.append("None.")

            if arm.contradictory_verdicts:
                lines += [
                    "",
                    f"### Contradictory verdicts ({len(arm.contradictory_verdicts)})",
                    "",
                    "The model named an impersonated brand while labelling the page as "
                    "something other than phishing.",
                    "",
                    *(
                        f"- {_code(p.fqdn)}: {_code(p.predicted)}, brand {_code(p.verdict_brand)}"
                        for p in arm.contradictory_verdicts
                    ),
                ]

            if arm.sweep is not None:
                lines += _sweep_section(arm.sweep)
            lines.append("")
        return "\n".join(lines)


def _code(value: object) -> str:
    """A Markdown code span that hostile text cannot break out of.

    Hostnames, model answers and stored paths reach this report, which is the kind
    of file that gets committed and rendered on GitHub. Inside a code span
    ``[x](url)`` stays text; a backtick, pipe or newline would end the span or the
    table row, so those are replaced.
    """
    text = str(value).replace("`", "'").replace("|", "/")
    return "`" + " ".join(text.split())[:200] + "`"


def _mistake_table(predictions: list[Prediction]) -> list[str]:
    rows = [
        "| Site | Expected | Predicted | Score | Screenshot |",
        "|---|---|---|---:|---|",
    ]
    rows += [
        f"| {_code(p.fqdn)} | {p.expected} | {_code(p.predicted)} | {p.score:.2f} | "
        f"{_code(p.screenshot) if p.screenshot else '-'} |"
        for p in predictions
    ]
    return rows


def _sweep_section(sweep: ThresholdSweep) -> list[str]:
    lines = [
        "",
        "### Alert threshold sweep",
        "",
        "Phishing class only: the threshold decides what reaches an analyst.",
        "",
        "| Threshold | Alerts | TP | FP | FN | Precision | Recall | F1 | |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    best = sweep.best_f1
    for point in sweep.points:
        marks = []
        if point.is_configured:
            marks.append("configured")
        if best is not None and point.threshold == best.threshold:
            marks.append("best F1")
        lines.append(
            f"| {point.threshold:.2f} | {point.alerts} | {point.true_positives} | "
            f"{point.false_positives} | {point.false_negatives} | {point.precision:.4f} | "
            f"{point.recall:.4f} | {point.f1:.4f} | {', '.join(marks)} |"
        )
    return lines


def write_report(report: EvaluationReport, out_dir: Path) -> tuple[Path, Path]:
    """Write both formats into a timestamped directory; returns their paths."""
    run_dir = out_dir / report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    json_path.write_text(report.to_json(), encoding="utf-8")
    markdown_path.write_text(report.to_markdown(), encoding="utf-8")
    return json_path, markdown_path
