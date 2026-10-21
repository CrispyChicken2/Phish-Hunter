"""Command-line entry point for the lookalike-hunter commands."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import re
import signal
from datetime import UTC, datetime, timedelta
from itertools import combinations
from pathlib import Path

from lookalike_hunter.alert.runner import build_sinks, run_alerts
from lookalike_hunter.archive import archive_captures, s3_uploader
from lookalike_hunter.backup import backup
from lookalike_hunter.capture.handoff import read_job
from lookalike_hunter.capture.runner import run_captures, visit_in_docker, visit_in_process
from lookalike_hunter.capture.visit import visit
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
from lookalike_hunter.eval.cloaking import DEFAULT_MAX_GAP, SideCapture, compare, load_side
from lookalike_hunter.eval.dataset import iter_dataset
from lookalike_hunter.eval.feeds import OPENPHISH_FEED_URL
from lookalike_hunter.eval.report import write_report
from lookalike_hunter.eval.runner import run_evaluation
from lookalike_hunter.eval.stats import discordant_counts, mcnemar_exact
from lookalike_hunter.ingest.pipeline import run_pipeline
from lookalike_hunter.ingest.sources import CertSource, CertstreamSource, ReplaySource
from lookalike_hunter.ingest.store import MatchStore, PendingCapture, connect_with_retry
from lookalike_hunter.logging import configure_logging, get_logger
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex
from lookalike_hunter.watch import IngestionStoppedError, watch

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
    """Pick the targets, have the capture container visit them, import the results.

    The browser runs in the container unless --outside-container is given: run
    by habit from the host shell, a browser exploit would land on the operator's
    own machine instead of in a throwaway container.
    """
    if os.environ.get(CAPTURE_CONTAINER_ENV):
        raise SystemExit(
            "inside the capture container, run `visit`: `capture` runs on the host, "
            "where the database is, and starts this container itself"
        )
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    targets = None
    if args.from_dataset is not None:
        targets = _dataset_targets(
            store, args.from_dataset, args.limit, settings.capture.recapture_after_h
        )
        log.info("capture.from_dataset", dataset=str(args.from_dataset), targets=len(targets))
    executor = visit_in_process if args.outside_container else visit_in_docker
    with contextlib.suppress(KeyboardInterrupt):
        stats = asyncio.run(run_captures(store, settings.capture, args.limit, targets, executor))
        log.info(
            "capture.done_all",
            attempted=stats.attempted,
            succeeded=stats.succeeded,
            rejected=stats.rejected,
            missing=stats.missing,
        )


def cmd_visit(settings: Settings, args: argparse.Namespace) -> None:
    """Container side of `capture`: visit one job's hostnames, write the results."""
    if not os.environ.get(CAPTURE_CONTAINER_ENV):
        raise SystemExit(
            "visit runs hostile pages and only runs inside the capture container; "
            "use `capture` (or `capture --outside-container`) on this machine"
        )
    job = read_job(args.root, args.job_id)
    asyncio.run(visit(job, args.root))


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


def refuse_feed_output_in_datasets(out: Path) -> None:
    """Feed entries must never be written under datasets/, which git tracks.

    The feed's terms do not allow redistribution (docs/feed-data.md). Feed entries belong
    in data/, which git ignores. Labelled feed sites go to datasets/feed/, but only after a
    human has labelled them, never as raw Feed entries.
    """
    # Both the folder next to the working directory and the one next to this checkout,
    # so an absolute path into the repository is refused from any directory.
    tracked_folders = {
        Path("datasets").resolve(),
        Path(__file__).resolve().parents[2] / "datasets",
    }
    target = out.resolve()
    if any(target == folder or folder in target.parents for folder in tracked_folders):
        raise SystemExit(
            f"refusing to write Feed entries to {out}: datasets/ is tracked by git. "
            "Use data/feed-entries.jsonl (see docs/feed-data.md)."
        )


def cmd_dataset(settings: Settings, args: argparse.Namespace) -> None:
    """Collect candidate sites for a human to label. Assigns no ground truth."""
    if args.fetch_feed or args.feed_file is not None:
        refuse_feed_output_in_datasets(args.out)
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
    # Per model: site -> was the answer right? Kept per site so models can be paired.
    answers: dict[str, dict[str, bool]] = {}
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
        answers[model] = {p.fqdn: p.expected == p.predicted for p in arm.predictions}
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

    # Paired test for every pair of models, on the sites both of them judged. The
    # p-value says whether the disagreements could be chance; it says nothing about cost.
    print("\nPaired comparison (exact McNemar, two-sided, sites judged by both models):")
    for (first, first_answers), (second, second_answers) in combinations(answers.items(), 2):
        only_first, only_second, shared = discordant_counts(first_answers, second_answers)
        p_value = mcnemar_exact(only_first, only_second)
        print(
            f"  {safe_text(first, 24)} vs {safe_text(second, 24)}: "
            f"{only_first} / {only_second} disagreements, {shared} shared sites, "
            f"p = {p_value:.4f}"
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


def cmd_watch(settings: Settings, args: argparse.Namespace) -> None:
    """Ingest continuously and run capture -> classify -> alert on a timer."""
    if os.environ.get(CAPTURE_CONTAINER_ENV):
        raise SystemExit("watch runs on the host, which starts the capture container itself")
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    index = VariantIndex.from_brands(settings.brands, settings.variants.swap_tlds)
    scorer = Scorer(settings.brands, settings.scoring, index)
    # --once is one triage pass (cron, a quick check): no point starting the stream.
    ingest = not (args.no_ingest or args.once)
    source = _build_source(settings, settings.ct.source, None) if ingest else None
    classifier, model = _build_classifier(settings)
    configured = settings.alert.webhook_url
    sinks = build_sinks(
        settings.alert.file_path, configured.get_secret_value() if configured else None
    )
    executor = visit_in_process if args.outside_container else visit_in_docker

    async def run() -> int:
        try:
            return await watch(
                settings,
                store,
                scorer,
                source,
                executor,
                classifier,
                model,
                sinks,
                args.interval or settings.watch.interval_s,
                cycles=1 if args.once else None,
            )
        finally:
            if isinstance(classifier, MistralClassifier):
                await classifier.aclose()

    with contextlib.suppress(KeyboardInterrupt):
        try:
            cycles = asyncio.run(run())
        except IngestionStoppedError as exc:
            raise SystemExit(str(exc)) from None
        log.info("watch.done", cycles=cycles)


def cmd_archive(settings: Settings, args: argparse.Namespace) -> None:
    """Upload captures older than the delay to S3, then delete their local copies."""
    bucket = settings.archive.bucket
    if not bucket:
        raise SystemExit("archive.bucket is not set (LH_ARCHIVE__BUCKET)")
    hours = args.older_than_hours or settings.archive.older_than_hours
    stats = archive_captures(
        settings.capture.output_dir,
        settings.archive.prefix,
        timedelta(hours=hours),
        s3_uploader(bucket),
        datetime.now(UTC),
    )
    log.info("archive.done", archived=stats.archived, failed=stats.failed)


def cmd_backup(settings: Settings, args: argparse.Namespace) -> None:
    """Upload a consistent snapshot of the database and the labelled dataset to S3."""
    bucket = settings.backup.bucket
    if not bucket:
        raise SystemExit("backup.bucket is not set (LH_BACKUP__BUCKET)")
    backup(
        settings.db_path,
        settings.dataset_path,
        settings.backup.prefix,
        datetime.now(UTC),
        s3_uploader(bucket),
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


def _describe(vantage: str, side: SideCapture) -> str:
    if not side.reachable:
        return f"    {safe_text(vantage, 30)}: {safe_text(side.status, 20)}"
    title = f' "{safe_text(side.title, 60)}"' if side.title else ""
    login = "  login form" if side.has_login_form else ""
    verdict = f"  verdict {safe_text(side.verdict, 12)}" if side.verdict else ""
    return (
        f"    {safe_text(vantage, 30)}: {side.http_status}  {safe_text(side.final_host, 80)}"
        f"{title}{login}{verdict}"
    )


def cmd_cloaking(settings: Settings, args: argparse.Namespace) -> None:
    """Compare the captures of the same sites from two Vantage points (CONTEXT.md)."""
    vantage = args.vantage or settings.capture.vantage
    if vantage is None:
        raise SystemExit("no vantage point to compare from: pass --vantage or set capture.vantage")
    db = args.db or settings.db_path
    other_db = args.against_db or db
    if vantage == args.against and db.resolve() == other_db.resolve():
        raise SystemExit("both sides are the same captures: pick another --against")
    report = compare(
        load_side(db, vantage, args.backend),
        load_side(other_db, args.against, args.backend),
        vantage,
        args.against,
        timedelta(hours=args.max_gap_h),
    )

    print(
        f"{len(report.pairs)} site(s) captured from both {safe_text(vantage, 30)} and "
        f"{safe_text(args.against, 30)} within {args.max_gap_h:g} h of each other"
    )
    print(
        f"  not compared: {report.too_far_apart} too far apart in time, "
        f"{report.only_first} only from {safe_text(vantage, 30)}, "
        f"{report.only_second} only from {safe_text(args.against, 30)}"
    )
    print(f"  unreachable on one side: {report.unreachable_on_one_side}")
    print(f"  different content:       {report.different_content}")
    print(f"  different verdict:       {report.different_verdict}")
    for pair in report.differing[: args.limit]:
        reasons = (
            (["unreachable on one side"] if pair.unreachable_on_one_side else [])
            + list(pair.content_differences)
            + (["verdict"] if pair.different_verdict else [])
        )
        print(f"\n{safe_text(pair.fqdn, 120)}  differs: {', '.join(reasons)}")
        print(_describe(vantage, pair.first))
        print(_describe(args.against, pair.second))


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

    visit_cmd = sub.add_parser("visit", help="(capture container only) Visit one capture job")
    visit_cmd.add_argument("job_id")
    visit_cmd.add_argument("--root", type=Path, default=Path("/app/captures"))
    visit_cmd.set_defaults(func=cmd_visit)

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

    watch_cmd = sub.add_parser(
        "watch", help="Run unattended: ingest CT, then capture, classify and alert on a timer"
    )
    watch_cmd.add_argument(
        "--interval", type=float, default=None, help="Seconds between cycles (watch.interval_s)"
    )
    watch_cmd.add_argument(
        "--once", action="store_true", help="One triage cycle on what is stored, then stop"
    )
    watch_cmd.add_argument(
        "--no-ingest",
        action="store_true",
        help="Only triage what is already stored (e.g. while `ingest` runs elsewhere)",
    )
    watch_cmd.add_argument(
        "--outside-container",
        action="store_true",
        help="Visit hostile sites from this machine instead of the capture container",
    )
    watch_cmd.set_defaults(func=cmd_watch)

    archive_cmd = sub.add_parser(
        "archive", help="Move captures older than the delay to object storage, then free them"
    )
    archive_cmd.add_argument(
        "--older-than-hours", type=float, default=None, help="archive.older_than_hours"
    )
    archive_cmd.set_defaults(func=cmd_archive)

    backup_cmd = sub.add_parser(
        "backup", help="Upload a consistent snapshot of the database and the dataset"
    )
    backup_cmd.set_defaults(func=cmd_backup)

    verdicts = sub.add_parser("verdicts", help="List recent verdicts with their evidence")
    verdicts.add_argument("--limit", type=int, default=20)
    verdicts.add_argument("--label", default=None, help="Only this label, e.g. phishing")
    verdicts.set_defaults(func=cmd_verdicts)

    cloaking = sub.add_parser(
        "cloaking", help="Compare captures of the same sites from two vantage points"
    )
    cloaking.add_argument(
        "--vantage", default=None, help="First side (default: capture.vantage of this config)"
    )
    cloaking.add_argument("--against", required=True, help="Second side, e.g. home")
    cloaking.add_argument("--db", type=Path, default=None, help="First side's database")
    cloaking.add_argument(
        "--against-db", type=Path, default=None, help="Second side's database (default: --db)"
    )
    cloaking.add_argument(
        "--max-gap-h",
        type=float,
        default=DEFAULT_MAX_GAP.total_seconds() / 3600,
        help="Only pair captures this close in time, in hours",
    )
    cloaking.add_argument(
        "--backend", default="mistral", help="Only compare verdicts from this backend"
    )
    cloaking.add_argument("--limit", type=int, default=30, help="Sites listed in detail")
    cloaking.set_defaults(func=cmd_cloaking)

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
