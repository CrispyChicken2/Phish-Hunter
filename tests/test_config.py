from pathlib import Path

import pytest

from lookalike_hunter.config import load_settings

DEFAULT = Path(__file__).parents[1] / "configs" / "default.yaml"


def test_default_config_loads() -> None:
    settings = load_settings(DEFAULT)
    assert {b.name for b in settings.brands} >= {"paypal", "apple"}
    assert 0 < settings.scoring.store_floor < settings.scoring.alert_threshold <= 1


def test_env_overrides_yaml(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LH_SCORING__ALERT_THRESHOLD", "0.95")
    assert load_settings(DEFAULT).scoring.alert_threshold == 0.95


def test_api_key_is_read_from_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("MISTRAL_API_KEY=secret-from-dotenv\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)

    key = load_settings(DEFAULT).mistral_api_key
    assert key is not None
    assert key.get_secret_value() == "secret-from-dotenv"


def test_api_key_absent_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.setenv("LH_CONFIG", str(DEFAULT))
    assert load_settings(DEFAULT).capture.timeout_s == 15
