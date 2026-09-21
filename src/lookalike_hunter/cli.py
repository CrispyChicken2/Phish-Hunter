"""Command-line entry point: ``lookalike-hunter {ingest,capture,classify,models,alerts}``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
from pathlib import Path

import duckdb

from lookalike_hunter.capture.runner import run_captures
from lookalike_hunter.classify.base import Classifier, StubClassifier
from lookalike_hunter.classify.mistral import MistralClassifier, list_vision_models
from lookalike_hunter.classify.runner import run_classifications
from lookalike_hunter.config import Settings, load_settings
from lookalike_hunter.ingest.pipeline import run_pipeline
from lookalike_hunter.ingest.sources import CertSource, CertstreamSource, ReplaySource
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.logging import configure_logging, get_logger
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex

log = get_logger(__name__)


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


def cmd_capture(settings: Settings, args: argparse.Namespace) -> None:
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    with contextlib.suppress(KeyboardInterrupt):
        stats = asyncio.run(run_captures(store, settings.capture, args.limit))
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
            ),
            settings.classify.model,
        )
    raise SystemExit(f"backend {backend!r} is not implemented yet")


def cmd_classify(settings: Settings, args: argparse.Namespace) -> None:
    store = MatchStore(settings.db_path, settings.scoring.alert_threshold)
    classifier, model = _build_classifier(settings)
    with contextlib.suppress(KeyboardInterrupt):
        stats = asyncio.run(
            run_classifications(
                store,
                classifier,
                model,
                args.limit or settings.classify.max_per_run,
                settings.classify.max_retries,
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
    with duckdb.connect(str(settings.db_path), read_only=True) as con:
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
        print(f"{first_seen:%Y-%m-%d %H:%M:%S}  {score:.2f}  {brand:<10} {domain:<40} "
              f"{n:>4} host(s)  e.g. {example}")  # fmt: skip


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
    capture.set_defaults(func=cmd_capture)

    classify = sub.add_parser("classify", help="Classify stored captures with the VLM backend")
    classify.add_argument("--limit", type=int, default=None)
    classify.set_defaults(func=cmd_classify)

    models = sub.add_parser("models", help="List vision models available to the API key")
    models.set_defaults(func=cmd_models)

    alerts = sub.add_parser("alerts", help="List recent alerts grouped by registered domain")
    alerts.add_argument("--limit", type=int, default=30)
    alerts.set_defaults(func=cmd_alerts)

    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    configure_logging(settings.log_level, settings.log_json)
    args.func(settings, args)


if __name__ == "__main__":
    main()
