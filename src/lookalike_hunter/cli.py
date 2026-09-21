"""Command-line entry point: ``lookalike-hunter {ingest,capture,alerts}``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
from pathlib import Path

import duckdb

from lookalike_hunter.capture.runner import run_captures
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

    alerts = sub.add_parser("alerts", help="List recent alerts grouped by registered domain")
    alerts.add_argument("--limit", type=int, default=30)
    alerts.set_defaults(func=cmd_alerts)

    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    configure_logging(settings.log_level, settings.log_json)
    args.func(settings, args)


if __name__ == "__main__":
    main()
