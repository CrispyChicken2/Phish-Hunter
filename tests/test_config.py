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
