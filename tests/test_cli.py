from datetime import UTC, datetime
from pathlib import Path

import pytest

from lookalike_hunter.capture.models import CaptureResult, CaptureStatus
from lookalike_hunter.capture.signals import PageSignals
from lookalike_hunter.cli import main
from lookalike_hunter.ingest.store import MatchStore

ROOT = Path(__file__).parents[1]


def test_replay_then_alerts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LH_DB_PATH", str(tmp_path / "cli.duckdb"))
    config = str(ROOT / "configs" / "default.yaml")
    fixture = str(ROOT / "tests" / "fixtures" / "certstream_sample.jsonl")

    main(["--config", config, "ingest", "--source", "replay", "--replay-path", fixture])
    main(["--config", config, "alerts"])

    out = capsys.readouterr().out
    assert "paypa1-secure-login.com" in out
    assert "account-verify.top" in out


def test_capture_command_runs_with_nothing_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LH_DB_PATH", str(tmp_path / "empty.duckdb"))
    config = str(ROOT / "configs" / "default.yaml")

    # No alerts stored: the command must be a clean no-op, not a crash.
    main(["--config", config, "capture"])


def test_classify_then_verdicts_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "cli.duckdb"
    monkeypatch.setenv("LH_DB_PATH", str(db))
    config = str(ROOT / "configs" / "default.yaml")
    shot = tmp_path / "shot.png"
    shot.write_bytes(b"\x89PNG-fake")
    MatchStore(db, 0.7).save_capture(
        CaptureResult(
            fqdn="appleid-security.com",
            url="https://appleid-security.com/",
            status=CaptureStatus.OK,
            captured_at=datetime.now(UTC),
            duration_ms=500,
            screenshot_path=shot,
            signals=PageSignals(title="Sign in", form_count=1, has_password_input=True),
        )
    )

    main(["--config", config, "classify"])
    main(["--config", config, "verdicts", "--label", "phishing"])

    out = capsys.readouterr().out
    assert "appleid-security.com" in out
    assert "phishing" in out
    assert "screenshot:" in out
