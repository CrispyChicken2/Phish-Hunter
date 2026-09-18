"""Ingestion loop: CT messages -> Candidates -> Matches -> DuckDB, in time/size batches."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

from lookalike_hunter.ingest.parse import Certificate, MalformedMessageError, parse_message
from lookalike_hunter.ingest.sources import CertSource
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.logging import get_logger
from lookalike_hunter.scoring.scorer import Match, Scorer

log = get_logger(__name__)

# Bound on the in-memory set of recently scored hostnames (cleared when full).
_SEEN_CAPACITY = 1_000_000


@dataclass
class PipelineStats:
    messages: int = 0
    certificates: int = 0
    malformed: int = 0
    hostnames_scored: int = 0
    matches_buffered: int = 0
    matches_new: int = 0


async def run_pipeline(
    source: CertSource,
    scorer: Scorer,
    store: MatchStore,
    flush_interval_s: float,
    flush_max_rows: int,
    max_messages: int | None = None,
) -> PipelineStats:
    stats = PipelineStats()
    buffer: list[tuple[Certificate, Match]] = []
    seen: set[str] = set()
    last_flush = time.monotonic()

    def flush() -> None:
        nonlocal last_flush
        new = store.write(buffer)
        stats.matches_new += new
        log.info("ct.flush", written=new, buffered=len(buffer), **asdict(stats))
        buffer.clear()
        last_flush = time.monotonic()

    try:
        async for message in source.messages():
            stats.messages += 1
            try:
                cert = parse_message(message)
            except MalformedMessageError as exc:
                stats.malformed += 1
                log.warning("ct.message.malformed", error=str(exc))
                cert = None
            if cert is not None:
                stats.certificates += 1
                for hostname in cert.domains:
                    if hostname in seen:
                        continue
                    if len(seen) >= _SEEN_CAPACITY:
                        seen.clear()
                    seen.add(hostname)
                    stats.hostnames_scored += 1
                    for match in scorer.score(hostname, cert.issuer_org):
                        buffer.append((cert, match))
                        stats.matches_buffered += 1

            if len(buffer) >= flush_max_rows or time.monotonic() - last_flush >= flush_interval_s:
                flush()
            if max_messages is not None and stats.messages >= max_messages:
                break
    finally:
        # Also runs on Ctrl+C / cancellation so buffered Matches are not lost.
        flush()
    return stats
