"""Classifier interface, retry policy and a model-free stub backend."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.logging import get_logger

log = get_logger(__name__)


class ClassificationError(Exception):
    """The backend could not produce a usable verdict for this attempt."""

    def __init__(
        self, message: str, *, retryable: bool = True, retry_after_s: float | None = None
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        # Honoured over our own backoff when the API says how long to wait.
        self.retry_after_s = retry_after_s


@dataclass(frozen=True, slots=True)
class ClassificationInput:
    fqdn: str
    suspected_brand: str
    screenshot_path: Path
    final_url: str | None = None
    signals: PageSignals | None = None


class Classifier(Protocol):
    name: str

    async def classify(self, item: ClassificationInput) -> Verdict: ...


class StubClassifier:
    """Deterministic, model-free baseline.

    Exists so the pipeline, the CLI and the tests run with no API key and no GPU.
    It is also the "signals only" arm of the Day 3 comparison against a real VLM.
    """

    name = "stub"

    async def classify(self, item: ClassificationInput) -> Verdict:
        signals = item.signals
        if signals is None:
            return Verdict(
                label=Label.UNKNOWN, confidence=0.3, evidence="No DOM signals available."
            )
        if signals.has_login_form:
            brand = item.suspected_brand
            exfil = signals.cross_domain_form_targets
            return Verdict(
                label=Label.PHISHING,
                confidence=0.8 if exfil else 0.6,
                brand_impersonated=brand,
                evidence=(
                    f"Login form on {item.fqdn}"
                    + (f", posting to {', '.join(exfil)}" if exfil else "")
                    + "."
                ),
            )
        if signals.form_count == 0 and not signals.title:
            return Verdict(
                label=Label.PARKED, confidence=0.5, evidence="No forms and no page title."
            )
        return Verdict(
            label=Label.UNKNOWN,
            confidence=0.4,
            evidence="No login form detected; a screenshot is needed to decide.",
        )


async def classify_with_retries(
    classifier: Classifier,
    item: ClassificationInput,
    max_retries: int,
    base_delay_s: float = 1.0,
) -> Verdict:
    """Call the backend, retrying transient failures and malformed model output.

    Malformed output is retryable on purpose: a VLM that ignored the JSON contract
    once often complies on a second attempt.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return await classifier.classify(item)
        except ClassificationError as exc:
            if not exc.retryable or attempt >= max_retries:
                raise
            delay = exc.retry_after_s or base_delay_s * 2 ** (attempt - 1)
            log.warning(
                "classify.retry",
                backend=classifier.name,
                fqdn=item.fqdn,
                attempt=attempt,
                error=str(exc)[:200],
                retry_in_s=delay,
            )
            await asyncio.sleep(delay)
