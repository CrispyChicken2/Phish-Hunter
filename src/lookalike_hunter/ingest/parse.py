"""Parse certstream-format messages (certstream-server-go / calidog) into Certificates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


class MalformedMessageError(ValueError):
    """A certificate_update message missing fields we rely on."""


@dataclass(frozen=True, slots=True)
class Certificate:
    sha256: str  # hex, lowercase, no colons
    seen_at: datetime
    issuer_org: str | None
    not_before: datetime
    not_after: datetime
    ct_log: str | None
    domains: tuple[str, ...]


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
