"""Alerting: who gets told, once, and with hostile text made safe to read."""

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from lookalike_hunter.alert.runner import build_sinks, run_alerts
from lookalike_hunter.alert.sinks import (
    AlertDeliveryError,
    FileSink,
    Notification,
    WebhookSink,
    defang,
)
from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.classify.schema import Label, Verdict
from lookalike_hunter.ingest.store import MatchStore

NOW = datetime(2026, 9, 28, 9, 0, tzinfo=UTC)


def notification(**overrides: object) -> Notification:
    defaults = {
        "fqdn": "appleid-security.com",
        "brand": "apple",
        "label": "phishing",
        "confidence": 0.93,
        "score": 0.85,
        "evidence": "Apple ID sign-in form on a domain Apple does not own.",
        "screenshot": "appleid-security.com/shot.png",
        "final_url": "https://appleid-security.com/login",
        "detected_at": NOW,
    }
    return Notification(**{**defaults, **overrides})  # type: ignore[arg-type]


def store_with_verdict(
    tmp_path: Path, label: Label = Label.PHISHING, confidence: float = 0.93
) -> MatchStore:
    store = MatchStore(tmp_path / "t.duckdb", 0.7)
    store.save_capture(
        CaptureResult(
            fqdn="appleid-security.com",
            url="https://appleid-security.com/",
            status=CaptureStatus.OK,
            captured_at=NOW,
            duration_ms=800,
            final_url="https://appleid-security.com/login",
            screenshot_path=Path("appleid-security.com/shot.png"),
        )
    )
    store.save_verdict(
        capture_id=1,
        fqdn="appleid-security.com",
        backend="mistral",
        model="m",
        verdict=Verdict(label=label, confidence=confidence, evidence="Sign-in form."),
        classified_at=NOW,
    )
    return store


# ------------------------------------------------------------------- safe output


def test_urls_are_defanged() -> None:
    """A chat client turns URLs into links; one reflex click opens the real page."""
    assert defang("https://evil.example.com/login") == "hxxps://evil[.]example[.]com/login"
    assert defang("http://a.b") == "hxxp://a[.]b"


def test_control_characters_are_stripped_from_every_field() -> None:
    hostile = notification(
        fqdn="evil\x1b[2Jcom",
        evidence="text\x07with\x1b[31mescapes",
    )

    payload = hostile.as_dict()
    text = hostile.as_text()

    assert "\x1b" not in json.dumps(payload) and "\x07" not in json.dumps(payload)
    assert "\x1b" not in text and "\x07" not in text


# ------------------------------------------------------------------------- sinks


def test_file_sink_appends_one_json_object_per_finding(tmp_path: Path) -> None:
    sink = FileSink(tmp_path / "nested" / "alerts.jsonl")

    sink.send(notification())
    sink.send(notification(fqdn="second.com"))

    lines = (tmp_path / "nested" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["fqdn"] == "appleid-security.com"
    assert json.loads(lines[1])["fqdn"] == "second.com"


def test_webhook_sink_posts_text_and_structure() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    sink = WebhookSink(
        "https://hooks.example/x", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    sink.send(notification())

    payload = json.loads(seen[0].content)
    assert "appleid-security.com" in payload["text"]  # human-readable
    assert payload["label"] == "phishing"  # machine-readable
    assert "hxxps://" in payload["text"]  # defanged in the prose


def test_webhook_failure_is_raised_so_the_finding_is_retried() -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="nope")

    sink = WebhookSink(
        "https://hooks.example/x", client=httpx.Client(transport=httpx.MockTransport(failing))
    )

    with pytest.raises(AlertDeliveryError):
        sink.send(notification())


# ------------------------------------------------------------------------ policy


def test_phishing_verdict_is_sent_once(tmp_path: Path) -> None:
    store = store_with_verdict(tmp_path)
    sink = FileSink(tmp_path / "alerts.jsonl")

    first = run_alerts(store, [sink], min_confidence=0.6, limit=10)
    second = run_alerts(store, [sink], min_confidence=0.6, limit=10)

    assert first.sent == 1
    assert second.considered == 0  # an alerting tool that repeats itself gets muted
    assert len((tmp_path / "alerts.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def test_parked_verdicts_are_not_announced(tmp_path: Path) -> None:
    """Most alerts are parking pages; telling a human about them is the noise."""
    store = store_with_verdict(tmp_path, label=Label.PARKED)

    stats = run_alerts(store, [FileSink(tmp_path / "a.jsonl")], min_confidence=0.6, limit=10)

    assert stats.sent == 0


def test_low_confidence_is_held_back(tmp_path: Path) -> None:
    store = store_with_verdict(tmp_path, confidence=0.4)

    stats = run_alerts(store, [FileSink(tmp_path / "a.jsonl")], min_confidence=0.6, limit=10)

    assert stats.sent == 0


def test_a_finding_nobody_received_stays_pending(tmp_path: Path) -> None:
    """Delivery failed, so it must not be marked as announced."""
    store = store_with_verdict(tmp_path)

    class BrokenSink:
        name = "broken"

        def send(self, notification: Notification) -> None:
            raise AlertDeliveryError("down")

    first = run_alerts(store, [BrokenSink()], min_confidence=0.6, limit=10)
    retry = run_alerts(store, [FileSink(tmp_path / "a.jsonl")], min_confidence=0.6, limit=10)

    assert first.sent == 0 and first.failed == 1
    assert retry.sent == 1  # the next run picks it up


def test_one_working_sink_is_enough_to_mark_it_sent(tmp_path: Path) -> None:
    store = store_with_verdict(tmp_path)

    class BrokenSink:
        name = "broken"

        def send(self, notification: Notification) -> None:
            raise AlertDeliveryError("down")

    stats = run_alerts(
        store, [BrokenSink(), FileSink(tmp_path / "a.jsonl")], min_confidence=0.6, limit=10
    )

    assert stats.sent == 1 and stats.failed == 1


def test_no_sinks_configured_is_reported_not_silent(tmp_path: Path) -> None:
    stats = run_alerts(store_with_verdict(tmp_path), [], min_confidence=0.6, limit=10)
    assert stats.sent == 0


def test_build_sinks_defaults_to_the_file(tmp_path: Path) -> None:
    assert [s.name for s in build_sinks(tmp_path / "a.jsonl", None)] == ["file"]
    assert [s.name for s in build_sinks(tmp_path / "a.jsonl", "https://x")] == ["file", "webhook"]
    assert build_sinks(None, None) == []
