from pathlib import Path

import pytest

from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.classify.base import (
    ClassificationError,
    ClassificationInput,
    StubClassifier,
    classify_with_retries,
)
from lookalike_hunter.classify.schema import Label, Verdict

SHOT = Path("shot.png")


def item(signals: PageSignals | None) -> ClassificationInput:
    return ClassificationInput("appleid-security.com", "apple", SHOT, signals=signals)


async def test_stub_flags_login_form_as_phishing() -> None:
    signals = PageSignals(
        title="Sign in",
        form_count=1,
        has_password_input=True,
        cross_domain_form_targets=["exfil.ru"],
    )
    verdict = await StubClassifier().classify(item(signals))

    assert verdict.label is Label.PHISHING
    assert verdict.brand_impersonated == "apple"
    assert "exfil.ru" in verdict.evidence


async def test_stub_calls_empty_page_parked() -> None:
    verdict = await StubClassifier().classify(item(PageSignals()))
    assert verdict.label is Label.PARKED


async def test_stub_is_unknown_without_signals() -> None:
    assert (await StubClassifier().classify(item(None))).label is Label.UNKNOWN


class _FlakyClassifier:
    name = "flaky"

    def __init__(self, failures: int, retryable: bool = True) -> None:
        self.failures = failures
        self.retryable = retryable
        self.calls = 0

    async def classify(self, item: ClassificationInput) -> Verdict:
        self.calls += 1
        if self.calls <= self.failures:
            raise ClassificationError("boom", retryable=self.retryable)
        return Verdict(label=Label.PARKED, confidence=0.5, evidence="ok")


async def test_retries_until_success() -> None:
    classifier = _FlakyClassifier(failures=2)
    verdict = await classify_with_retries(classifier, item(None), max_retries=3, base_delay_s=0)

    assert verdict.label is Label.PARKED
    assert classifier.calls == 3


async def test_gives_up_after_max_retries() -> None:
    classifier = _FlakyClassifier(failures=99)
    with pytest.raises(ClassificationError):
        await classify_with_retries(classifier, item(None), max_retries=2, base_delay_s=0)
    assert classifier.calls == 2


async def test_non_retryable_error_fails_immediately() -> None:
    classifier = _FlakyClassifier(failures=99, retryable=False)
    with pytest.raises(ClassificationError):
        await classify_with_retries(classifier, item(None), max_retries=5, base_delay_s=0)
    assert classifier.calls == 1
