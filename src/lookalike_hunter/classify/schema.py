"""The verdict a vision-language model must produce, and the prompt that asks for it.

The model output is untrusted text: it is parsed into :class:`Verdict` and rejected
if it does not fit. Nothing downstream ever sees a raw model string.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

from lookalike_hunter.capture.signals import PageSignals


class Label(StrEnum):
    PHISHING = "phishing"
    PARKED = "parked"
    LEGITIMATE = "legitimate"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class Verdict(BaseModel):
    """Structured classification of one captured page."""

    label: Label
    confidence: float = Field(ge=0.0, le=1.0)
    brand_impersonated: str | None = None
    evidence: str = Field(max_length=1000)

    @field_validator("brand_impersonated", mode="before")
    @classmethod
    def _empty_to_none(cls, value: object) -> object:
        if isinstance(value, str) and value.strip().lower() in {"", "none", "null", "n/a"}:
            return None
        return value


SYSTEM_PROMPT = """You are a phishing analyst. You are shown a screenshot of a website \
whose domain name resembles a known brand, plus signals extracted from its HTML.

Classify the page into exactly one label:
- "phishing": imitates a brand to steal credentials, payment or identity data.
- "parked": no real content: domain for sale, registrar placeholder, ads-only, \
default server page, or an empty/error page.
- "legitimate": a genuine site that merely resembles the brand name, including the \
brand's own site and unrelated businesses.
- "unknown": the screenshot is unreadable or too ambiguous to decide.

Rules:
- Judge what the page shows, not the domain name alone. A suspicious name with a \
parking page is "parked", not "phishing".
- A login form asking for brand credentials on a domain the brand does not own is \
strong evidence of phishing.
- brand_impersonated is the brand the page visually imitates, or null if none.
- evidence: one or two sentences citing what you saw (logo, form, wording).
- confidence is your certainty in the label, from 0 to 1.

Answer with a single JSON object and nothing else:
{"label": "...", "confidence": 0.0, "brand_impersonated": "...", "evidence": "..."}"""


def build_user_prompt(
    fqdn: str, suspected_brand: str, final_url: str | None, signals: PageSignals | None
) -> str:
    """Context given alongside the screenshot. Facts only: no verdict hints."""
    lines = [
        f"Domain visited: {fqdn}",
        f"Brand the domain resembles: {suspected_brand}",
        f"Final URL after redirects: {final_url or 'unknown'}",
    ]
    if signals is not None:
        lines += [
            f"Page title: {signals.title or '(none)'}",
            f"Forms: {signals.form_count}",
            f"Password inputs: {signals.password_input_count}",
            f"Credential-like field present: {signals.has_credential_field}",
            f"Forms posting to another domain: {signals.cross_domain_form_targets or 'none'}",
            f"Iframes: {signals.iframe_count}",
        ]
    return "\n".join(lines)


def parse_verdict(raw: str) -> Verdict:
    """Parse a model reply into a Verdict, tolerating code fences and stray prose."""
    payload = _extract_json_object(raw)
    try:
        return Verdict.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"model output does not match the verdict schema: {exc}") from exc


def _extract_json_object(raw: str) -> Any:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```")[1].removeprefix("json").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"no JSON object in model output: {raw[:200]!r}")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in model output: {raw[:200]!r}") from exc
