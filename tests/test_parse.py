import json
from pathlib import Path
from typing import Any

import pytest

from lookalike_hunter.ingest.parse import MalformedMessageError, parse_message

FIXTURE = Path(__file__).parent / "fixtures" / "certstream_sample.jsonl"


def load() -> list[dict[str, Any]]:
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]


def test_parses_real_messages() -> None:
    certs = [c for m in load() if (c := parse_message(m)) is not None]
    assert len(certs) == 25
    first = certs[0]
    assert first.domains == ("paypa1-secure-login.com", "*.paypa1-secure-login.com")
    assert first.issuer_org == "Let's Encrypt"
    assert len(first.sha256) == 64 and ":" not in first.sha256
    assert first.not_before < first.not_after
    assert first.seen_at.tzinfo is not None


def test_null_all_domains_becomes_empty_tuple() -> None:
    certs = [c for m in load() if (c := parse_message(m)) is not None]
    assert any(c.domains == () for c in certs)


def test_non_certificate_messages_are_skipped() -> None:
    assert parse_message({"message_type": "heartbeat"}) is None


def test_malformed_certificate_raises() -> None:
    bad = load()[0]
    del bad["data"]["leaf_cert"]["not_after"]
    with pytest.raises(MalformedMessageError, match="not_after"):
        parse_message(bad)
