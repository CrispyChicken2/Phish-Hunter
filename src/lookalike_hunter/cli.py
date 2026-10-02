"""Command-line entry point for the lookalike-hunter commands."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import re
import signal
from pathlib import Path

from lookalike_hunter.alert.runner import build_sinks, run_alerts
from lookalike_hunter.capture.runner import run_captures
from lookalike_hunter.classify.base import Classifier, StubClassifier
from lookalike_hunter.classify.mistral import MistralClassifier, list_vision_models
from lookalike_hunter.classify.runner import run_classifications
from lookalike_hunter.config import Settings, load_settings
from lookalike_hunter.eval.arms import ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM
from lookalike_hunter.eval.build import (
    candidates_from_alerts,
    candidates_from_feed,
    fetch_feed,
    hard_negative_candidates,
    write_candidates,
)
from lookalike_hunter.eval.dataset import iter_dataset
from lookalike_hunter.eval.feeds import OPENPHISH_FEED_URL
from lookalike_hunter.eval.report import write_report
from lookalike_hunter.eval.runner import run_evaluation
from lookalike_hunter.ingest.pipeline import run_pipeline
from lookalike_hunter.ingest.sources import CertSource, CertstreamSource, ReplaySource
from lookalike_hunter.ingest.store import MatchStore, PendingCapture, connect_with_retry
from lookalike_hunter.logging import configure_logging, get_logger
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex

log = get_logger(__name__)

# Page titles, hostnames and model evidence are attacker-influenced text. Printing
# them raw lets a crafted page drive the terminal with ANSI escape sequences.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Set by the capture image (docker/capture/Dockerfile) and nowhere else.
CAPTURE_CONTAINER_ENV = "LH_CAPTURE_CONTAINER"


def safe_text(value: object, limit: int = 300) -> str:
    """Strip control characters so hostile text cannot rewrite the terminal."""
    return _CONTROL_CHARS.sub(" ", str(value))[:limit]


def _build_source(settings: Settings, source: str, replay_path: Path | None) -> CertSource:
    if source == "replay":
        path = replay_path or settings.ct.replay_path
        if path is None:
            raise SystemExit("--replay-path (or ct.replay_path in config) is required for replay")
        return ReplaySource(path)
    return CertstreamSource(settings.ct.certstream_url, settings.ct.reconnect_max_backoff_s)


def cmd_ingest(settings: Settings, args: argparse.Namespace) -> None:
    index = VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds)
    log.info("variants.ready", variants=len(index), brands=len(settings.brands))
    scorer = Scorer(settings.brands, settings.scoring, index)
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    source = _build_source(settings, args.source or settings.ct.source, args.replay_path)
    with contextlib.suppress(KeyboardInterrupt):
        stats = asyncio.run(
            run_pipeline(
                source,
                scorer,
                store,
                settings.ct.flush_interval_s,
                settings.ct.flush_max_rows,
                args.max_messages,
            )
        )
        log.info("ingest.done", **vars(stats))


def _dataset_targets(
    store: MatchStore, dataset_path: Path, limit: int | None, recapture_after_h: float
) -> list[PendingCapture]:
    """Dataset entries still needing a screenshot, labelled or not."""
    sites = {s.fqdn: s for s in iter_dataset(dataset_path, allow_unlabelled=True)}
    todo = store.uncaptured(list(sites), recapture_after_h)[: limit or len(sites)]
    return [
        PendingCapture(fqdn=fqdn, registered_domain=fqdn, brand=sites[fqdn].brand or "", score=0.0)
        for fqdn in todo
    ]


def cmd_capture(settings: Settings, args: argparse.Namespace) -> None:
    # The one command that runs attacker code. Run by habit from the host shell,
    # a browser exploit would land on the operator's own machine instead of in a
    # throwaway container, so that has to be asked for explicitly.
    if not os.environ.get(CAPTURE_CONTAINER_ENV) and not args.outside_container:
        raise SystemExit(
            "capture visits hostile sites and belongs in the hardened container:\n"
            "    docker compose run --rm capture capture\n"
            "Pass --outside-container to run it on this machine anyway."
        )
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    targets = None
    if args.from_dataset is not None:
        targets = _dataset_targets(
            store, args.from_dataset, args.limit, settings.capture.recapture_after_h
        )
        log.info("capture.from_dataset", dataset=str(args.from_dataset), targets=len(targets))
    with contextlib.suppress(KeyboardInterrupt):
        stats = asyncio.run(run_captures(store, settings.capture, args.limit, targets))
        log.info("capture.done_all", attempted=stats.attempted, succeeded=stats.succeeded)


def _build_classifier(settings: Settings) -> tuple[Classifier, str | None]:
    backend = settings.classify.backend
    if backend == "stub":
        return StubClassifier(), None
    if backend == "mistral":
        key = settings.mistral_api_key
        if key is None:
            raise SystemExit(
                "MISTRAL_API_KEY is not set. Put it in .env or the environment, "
                "or set classify.backend to 'stub'."
            )
        return (
            MistralClassifier(
                key.get_secret_value(),
                settings.classify.model,
                settings.classify.api_base,
                settings.classify.timeout_s,
                cost_per_1k_prompt_usd=settings.classify.cost_per_1k_prompt_usd,
                cost_per_1k_completion_usd=settings.classify.cost_per_1k_completion_usd,
            ),
            settings.classify.model,
        )
    raise SystemExit(f"backend {backend!r} is not implemented yet")


def cmd_classify(settings: Settings, args: argparse.Namespace) -> None:
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    classifier, model = _build_classifier(settings)
    if args.retry_failed:
        cleared = store.clear_failed_verdicts(classifier.name)
        log.info("classify.retry_failed", cleared=cleared)
    if args.force:
        cleared = store.clear_verdicts(classifier.name, model, args.limit)
        log.info("classify.force", cleared=cleared, model=model)
    with contextlib.suppress(KeyboardInterrupt):
        stats = asyncio.run(
            run_classifications(
                store,
                classifier,
                model,
                args.limit or settings.classify.max_per_run,
                settings.classify.max_retries,
                settings.capture.output_dir,
                settings.classify.min_interval_s,
                settings.classify.retry_base_delay_s,
            )
        )
        log.info("classify.done_all", classified=stats.classified, failed=stats.failed)


def cmd_models(settings: Settings, args: argparse.Namespace) -> None:
    """List the vision models this Mistral account can call."""
    key = settings.mistral_api_key
    if key is None:
        raise SystemExit("MISTRAL_API_KEY is not set (put it in .env).")
    models = asyncio.run(list_vision_models(key.get_secret_value(), settings.classify.api_base))
    if not models:
        print("No vision-capable models available on this account.")
        return
    print("Vision models available to this account:")
    for name in models:
        marker = " <- configured" if name == settings.classify.model else ""
        print(f"  {name}{marker}")


def cmd_alerts(settings: Settings, args: argparse.Namespace) -> None:
    """Print the latest alerts, one registered domain per line."""
    with connect_with_retry(settings.db_path, read_only=True) as con:
        rows = con.execute(
            """
            SELECT registered_domain, brand, max(score) AS score, count(*) AS hostnames,
                   min(first_seen_at) AS first_seen, arg_max(fqdn, score) AS example
            FROM matches WHERE is_alert
            GROUP BY ALL ORDER BY first_seen DESC LIMIT ?
            """,
            [args.limit],
        ).fetchall()
    for domain, brand, score, n, first_seen, example in rows:
        print(
            f"{first_seen:%Y-%m-%d %H:%M:%S}  {score:.2f}  {safe_text(brand, 10):<10} "
            f"{safe_text(domain, 40):<40} {n:>4} host(s)  e.g. {safe_text(example, 60)}"
        )


def cmd_dataset(settings: Settings, args: argparse.Namespace) -> None:
    """Collect candidate sites for a human to label. Assigns no ground truth."""
    candidates = []
    if args.feed_file is not None:
        text = args.feed_file.read_text(encoding="utf-8", errors="replace")
        candidates += candidates_from_feed(text, settings.brands, source=args.feed_file.name)
    elif args.fetch_feed:
        log.info("dataset.fetching", url=args.feed_url)
        candidates += candidates_from_feed(
            fetch_feed(args.feed_url), settings.brands, source="openphish"
        )
    if args.from_alerts:
        candidates += candidates_from_alerts(settings.db_path, args.from_alerts)
    if args.hard_negatives:
        candidates += hard_negative_candidates()

    if not candidates:
        raise SystemExit(
            "nothing to add: pass --fetch-feed, --feed-file, --from-alerts or --hard-negatives"
        )

    added, skipped = write_candidates(args.out, candidates)
    print(f"{added} candidate(s) added to {args.out} ({skipped} already present)")
    print('Now set "expected" on each new line: see docs/labelling-protocol.md')


def cmd_compare_models(settings: Settings, args: argparse.Namespace) -> None:
    """Run the vision arm once per model over the same dataset and tabulate.

    Same sites, same captures, same labels: only the model changes, so the
    accuracy-against-cost trade is the only thing the table can be showing.
    """
    index = VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds)
    scorer = Scorer(settings.brands, settings.scoring, index)

    rows = []
    for model in args.models:
        report = run_evaluation(
            args.dataset,
            scorer,
            settings.scoring.alert_threshold,
            arms=(ARM_SCORING_PLUS_VLM,),
            db_path=settings.db_path,
            backend=args.backend,
            model=model,
        )
        arm = report.arms[ARM_SCORING_PLUS_VLM]
        spend = arm.cost
        rows.append(
            (
                model,
                arm.evaluated,
                arm.metrics.accuracy,
                arm.metrics.macro_f1,
                spend.classify_ms / arm.evaluated if spend and arm.evaluated else 0.0,
                spend.tokens if spend else 0,
                spend.cost_usd if spend else 0.0,
            )
        )

    header = f"{'model':24} {'judged':>6} {'accuracy':>9} {'macroF1':>8} {'ms/site':>8} {'tokens':>8} {'USD':>8}"  # noqa: E501
    print(header)
    print("-" * len(header))
    for model, judged, accuracy, f1, ms, tokens, cost in rows:
        print(
            f"{safe_text(model, 24):24} {judged:>6} {accuracy:>8.2%} {f1:>8.4f} "
            f"{ms:>8.0f} {tokens:>8} {cost:>8.4f}"
        )


def cmd_evaluate(settings: Settings, args: argparse.Namespace) -> None:
    """Measure the pipeline against a labelled dataset and write a report."""
    index = VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds)
    scorer = Scorer(settings.brands, settings.scoring, index)
    report = run_evaluation(
        args.dataset,
        scorer,
        settings.scoring.alert_threshold,
        arms=tuple(args.arms),
        db_path=settings.db_path,
        backend=args.backend,
        model=args.model,
    )
    json_path, markdown_path = write_report(report, args.out)

    for arm in report.arms.values():
        m = arm.metrics
        print(f"{arm.name}: accuracy {m.accuracy:.2%} ({m.correct}/{m.total}), "
              f"macro F1 {m.macro_f1:.4f}, {len(arm.mistakes)} mistake(s), "
              f"{arm.excluded} excluded")  # fmt: skip
        for cls in m.per_class.values():
            print(
                f"    {safe_text(cls.label, 12):<12} "
                f"P {cls.precision:.4f}  R {cls.recall:.4f}  F1 {cls.f1:.4f}  "
                f"(support {cls.support})"
            )
    print(f"\nreport: {markdown_path}\n        {json_path}")


def cmd_alert(settings: Settings, args: argparse.Namespace) -> None:
    """Notify about new findings that meet the alert policy."""
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    configured = settings.alert.webhook_url
    sinks = build_sinks(
        args.file or settings.alert.file_path,
        args.webhook or (configured.get_secret_value() if configured else None),
    )
    stats = run_alerts(
        store,
        sinks,
        settings.alert.min_confidence,
        args.limit or settings.alert.max_per_run,
        tuple(settings.alert.labels),
    )
    print(
        f"{stats.sent} notification(s) sent from {stats.considered} candidate(s)"
        + (f", {stats.failed} delivery failure(s)" if stats.failed else "")
    )


def cmd_verdicts(settings: Settings, args: argparse.Namespace) -> None:
    """Print the latest verdicts with the screenshot that backs each one."""
    with connect_with_retry(settings.db_path, read_only=True) as con:
        rows = con.execute(
            """
            SELECT v.classified_at, v.label, v.confidence, v.fqdn, v.brand_impersonated,
                   v.evidence, c.screenshot_path, v.backend
            FROM verdicts v JOIN captures c USING (capture_id)
            WHERE (? IS NULL OR v.label = ?)
            ORDER BY v.classified_at DESC, v.verdict_id DESC
            LIMIT ?
            """,
            [args.label, args.label, args.limit],
        ).fetchall()
    for at, label, confidence, fqdn, brand, evidence, shot, backend in rows:
        print(
            f"{at:%Y-%m-%d %H:%M}  {safe_text(label, 12):<12} {confidence:.2f}  "
            f"{safe_text(fqdn, 80)}  [{safe_text(backend, 20)}]"
        )
        if brand:
            print(f"    impersonates: {safe_text(brand, 60)}")
        if evidence:
            print(f"    evidence: {safe_text(evidence)}")
        if shot:
            print(f"    screenshot: {safe_text(shot, 200)}")


def install_shutdown_handler() -> None:
    """Turn SIGTERM into KeyboardInterrupt so buffered work is flushed.

    ``docker stop`` and most supervisors send SIGTERM, whose default action kills
    the process outright: the ingest pipeline would lose everything buffered since
    the last flush. Ctrl+C already raises KeyboardInterrupt.
    """

    def handler(signum: int, frame: object) -> None:
        log.info("shutdown.signal", signal=signal.Signals(signum).name)
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGBREAK"):  # SIGBREAK is Windows-only
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, handler)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="lookalike-hunter")
    parser.add_argument("--config", type=Path, default=None, help="YAML config path")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Consume CT logs and store scored matches")
    ingest.add_argument("--source", choices=["certstream", "replay"], default=None)
    ingest.add_argument("--replay-path", type=Path, default=None)
    ingest.add_argument("--max-messages", type=int, default=None)
    ingest.set_defaults(func=cmd_ingest)

    capture = sub.add_parser("capture", help="Passively visit alerts and store screenshots")
    capture.add_argument("--limit", type=int, default=None)
    capture.add_argument(
        "--from-dataset",
        type=Path,
        default=None,
        help="Capture the sites in a dataset file instead of pending alerts",
    )
    capture.add_argument(
        "--outside-container",
        action="store_true",
        help="Visit hostile sites from this machine instead of the capture container",
    )
    capture.set_defaults(func=cmd_capture)

    classify = sub.add_parser("classify", help="Classify stored captures with the VLM backend")
    classify.add_argument("--limit", type=int, default=None)
    classify.add_argument(
        "--retry-failed", action="store_true", help="Re-classify captures that errored"
    )
    classify.add_argument(
        "--force",
        action="store_true",
        help="Discard stored verdicts first, to measure a prompt or model change",
    )
    classify.set_defaults(func=cmd_classify)

    models = sub.add_parser("models", help="List vision models available to the API key")
    models.set_defaults(func=cmd_models)

    dataset = sub.add_parser("dataset", help="Collect candidate sites to label")
    dataset.add_argument("--out", type=Path, default=Path("datasets/eval.jsonl"))
    dataset.add_argument("--fetch-feed", action="store_true", help="Download the phishing feed")
    dataset.add_argument("--feed-url", default=OPENPHISH_FEED_URL)
    dataset.add_argument("--feed-file", type=Path, default=None, help="Use a local feed copy")
    dataset.add_argument("--from-alerts", type=int, default=0, help="Sample N captured alerts")
    dataset.add_argument("--hard-negatives", action="store_true", help="Seed known tricky cases")
    dataset.set_defaults(func=cmd_dataset)

    evaluate = sub.add_parser("evaluate", help="Measure accuracy against a labelled dataset")
    evaluate.add_argument("--dataset", type=Path, required=True, help="Labelled dataset (JSONL)")
    evaluate.add_argument("--out", type=Path, default=Path("data/eval"))
    evaluate.add_argument("--arms", nargs="+", default=[ARM_SCORING_ONLY, ARM_SCORING_PLUS_VLM])
    evaluate.add_argument(
        "--backend", default=None, help="Only use Verdicts from this classifier backend"
    )
    evaluate.add_argument(
        "--model", default=None, help="Only use Verdicts from this model, for comparisons"
    )
    evaluate.set_defaults(func=cmd_evaluate)

    compare = sub.add_parser("compare-models", help="Tabulate models over the same dataset")
    compare.add_argument("--dataset", type=Path, required=True)
    compare.add_argument("--models", nargs="+", required=True)
    compare.add_argument("--backend", default="mistral")
    compare.set_defaults(func=cmd_compare_models)

    alert = sub.add_parser("alert", help="Notify about new phishing verdicts")
    alert.add_argument("--limit", type=int, default=None)
    alert.add_argument("--file", type=Path, default=None, help="Override the JSONL sink path")
    alert.add_argument("--webhook", default=None, help="Override the webhook URL")
    alert.set_defaults(func=cmd_alert)

    verdicts = sub.add_parser("verdicts", help="List recent verdicts with their evidence")
    verdicts.add_argument("--limit", type=int, default=20)
    verdicts.add_argument("--label", default=None, help="Only this label, e.g. phishing")
    verdicts.set_defaults(func=cmd_verdicts)

    alerts = sub.add_parser("alerts", help="List recent alerts grouped by registered domain")
    alerts.add_argument("--limit", type=int, default=30)
    alerts.set_defaults(func=cmd_alerts)

    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    configure_logging(settings.log_level, settings.log_json)
    install_shutdown_handler()
    args.func(settings, args)


if __name__ == "__main__":
    main()
