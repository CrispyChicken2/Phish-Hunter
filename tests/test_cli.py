from pathlib import Path

import pytest

from lookalike_hunter.cli import main

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
