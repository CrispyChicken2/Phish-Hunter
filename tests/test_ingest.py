import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import duckdb
import pytest
from websockets.asyncio.server import ServerConnection, serve

from lookalike_hunter.config import load_settings
from lookalike_hunter.ingest.pipeline import run_pipeline
from lookalike_hunter.ingest.sources import CertstreamSource, ReplaySource
from lookalike_hunter.ingest.store import MatchStore
from lookalike_hunter.scoring.scorer import Scorer
from lookalike_hunter.variants.generator import VariantIndex

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "certstream_sample.jsonl"


@pytest.fixture(scope="module")
def scorer() -> Scorer:
    s = load_settings(ROOT / "configs" / "default.yaml")
    return Scorer(s.brands, s.scoring, VariantIndex.from_brands(s.brands, s.variants.swap_tlds))


async def test_replay_end_to_end(tmp_path: Path, scorer: Scorer) -> None:
    db = tmp_path / "t.duckdb"
    stats = await run_pipeline(
        ReplaySource(FIXTURE), scorer, MatchStore(db, 0.7), flush_interval_s=60, flush_max_rows=2
    )

    assert stats.messages == 26
    assert stats.certificates == 25
    assert stats.malformed == 0
    with duckdb.connect(str(db), read_only=True) as con:
        alerts = {r[0] for r in con.execute("SELECT fqdn FROM matches WHERE is_alert").fetchall()}
    assert {
        "paypa1-secure-login.com",
        "xn--pypal-4ve.com",
        "paypal.com.account-verify.top",
    } <= alerts
    assert "www.paypal.com" not in alerts


async def test_malformed_messages_are_counted_not_fatal(tmp_path: Path, scorer: Scorer) -> None:
    class Bad:
        async def messages(self) -> AsyncIterator[dict[str, Any]]:
            yield {"message_type": "certificate_update", "data": {}}

    stats = await run_pipeline(Bad(), scorer, MatchStore(tmp_path / "t.duckdb", 0.7), 60, 10)
    assert stats.malformed == 1


async def test_certstream_source_reconnects() -> None:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()[:2]

    async def handler(ws: ServerConnection) -> None:
        for line in lines:
            await ws.send(line)
        await ws.close()  # force a reconnect after each batch

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        source = CertstreamSource(f"ws://127.0.0.1:{port}/", max_backoff_s=0.01)
        received: list[dict[str, Any]] = []

        async def consume() -> None:
            async for message in source.messages():
                received.append(message)
                if len(received) == 4:
                    return

        await asyncio.wait_for(consume(), timeout=10)
    assert len(received) == 4  # 2 messages x 2 connections
