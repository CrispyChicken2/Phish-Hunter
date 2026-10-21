"""Parse certstream-format messages (certstream-server-go / calidog) into Certificates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


class MalformedMessageError(ValueError):
    """A certificate_update message missing fields we rely on."""


@dataclass(frozen=True, slots=True)
class Certificate:
    # hex, lowercase, no colons; or DERIVED_KEY_PREFIX + hex when the feed's is unusable
    sha256: str
    seen_at: datetime
    issuer_org: str | None
    not_before: datetime
    not_after: datetime
    ct_log: str | None
    domains: tuple[str, ...]


# The SHA-256 of zero bytes. certstream-server-go sends it for some certificates
# (measured: 39% of the Matches stored from 2026-09-21 to 10-03), so it identifies
# nothing: every such certificate was filed under the first one stored, and its
# Matches pointed at another site's certificate.
EMPTY_INPUT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Marks a key we derived, so it is never mistaken for a real fingerprint.
DERIVED_KEY_PREFIX = "issuer-serial:"


def _issuer_serial_key(leaf: dict[str, Any]) -> str:
    """A stable key for a certificate the feed gave no usable fingerprint for.

    Issuer and serial number identify a certificate (RFC 5280: an issuer never reuses
    a serial). A precertificate shares both with its final certificate, which is
    fine here: same names, same issuer. Without a serial, the validity and names
    stand in.
    """
    issuer = json.dumps(leaf.get("issuer") or {}, sort_keys=True)
    serial = str(leaf.get("serial_number") or "")
    identity = (
        f"{issuer}|{serial}"
        if serial
        else f"{issuer}|{leaf.get('not_before')}|{leaf.get('not_after')}|"
        + ",".join(sorted(leaf.get("all_domains") or ()))
    )
    return DERIVED_KEY_PREFIX + hashlib.sha256(identity.encode()).hexdigest()


def _ts(value: float) -> datetime:
    return datetime.fromtimestamp(value, tz=UTC)


def parse_message(message: dict[str, Any]) -> Certificate | None:
    """Return the Certificate in a message, or None for non-certificate messages.

    Raises MalformedMessageError when a certificate_update lacks required fields, so
    the caller can count and log it instead of silently dropping it.
    """
    if message.get("message_type") != "certificate_update":
        return None
    try:
        data = message["data"]
        leaf = data["leaf_cert"]
        sha256 = (leaf.get("sha256") or "").replace(":", "").lower()
        if sha256 in ("", EMPTY_INPUT_SHA256):
            sha256 = _issuer_serial_key(leaf)
        cert = Certificate(
            sha256=sha256,
            seen_at=_ts(float(data["seen"])),
            issuer_org=(leaf.get("issuer") or {}).get("O"),
            not_before=_ts(float(leaf["not_before"])),
            not_after=_ts(float(leaf["not_after"])),
            ct_log=(data.get("source") or {}).get("name"),
            # certstream-server-go sends null (not []) when a cert has no SAN/CN.
            domains=tuple(leaf.get("all_domains") or ()),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MalformedMessageError(f"{type(exc).__name__}: {exc}") from exc
    if not cert.sha256:
        raise MalformedMessageError("certificate without sha256")
    return cert
