import json
from pathlib import Path
from typing import Any

import duckdb
import pytest

from lookalike_hunter.ingest.parse import (
    DERIVED_KEY_PREFIX,
    EMPTY_INPUT_SHA256,
    MalformedMessageError,
    parse_message,
)

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


# ------------------------------------------------- certificates with no usable hash


def with_empty_hash(serial: str, domain: str) -> dict[str, Any]:
    """A message as certstream-server-go sends some: the SHA-256 of zero bytes."""
    message = load()[0]
    leaf = message["data"]["leaf_cert"]
    leaf["sha256"] = ":".join(EMPTY_INPUT_SHA256[i : i + 2] for i in range(0, 64, 2)).upper()
    leaf["serial_number"] = serial
    leaf["all_domains"] = [domain]
    return message


def test_the_empty_input_hash_is_replaced_by_issuer_and_serial() -> None:
    """Seen live: thousands of certificates shared that hash, so one row stood for all."""
    first = parse_message(with_empty_hash("01AB", "a.example"))
    second = parse_message(with_empty_hash("02CD", "b.example"))
    again = parse_message(with_empty_hash("01AB", "a.example"))

    assert first is not None and second is not None and again is not None
    assert first.sha256.startswith(DERIVED_KEY_PREFIX)
    assert first.sha256 != second.sha256  # two certificates, two keys
    assert first.sha256 == again.sha256  # the same certificate, the same key


def test_a_missing_hash_is_derived_too() -> None:
    message = with_empty_hash("01AB", "a.example")
    del message["data"]["leaf_cert"]["sha256"]

    cert = parse_message(message)

    assert cert is not None and cert.sha256.startswith(DERIVED_KEY_PREFIX)


def test_certificates_with_the_empty_hash_each_keep_their_own_row(tmp_path: Path) -> None:
    from lookalike_hunter.ingest.store import MatchStore
    from lookalike_hunter.scoring.scorer import Match, MatchFeatures

    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    rows = []
    for serial, host in (("01AB", "paypa1-a.com"), ("02CD", "paypa1-b.com")):
        cert = parse_message(with_empty_hash(serial, host))
        assert cert is not None
        rows.append((cert, Match(host, host, "paypal", 0.9, MatchFeatures())))
    store.write(rows)

    with duckdb.connect(str(store.db_path), read_only=True) as con:
        linked = con.execute(
            "SELECT m.fqdn, c.all_domains FROM matches m JOIN certificates c USING (cert_sha256)"
            " ORDER BY m.fqdn"
        ).fetchall()
    assert linked == [("paypa1-a.com", ["paypa1-a.com"]), ("paypa1-b.com", ["paypa1-b.com"])]
