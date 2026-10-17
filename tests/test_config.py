from pathlib import Path

import pytest

from lookalike_hunter.config import Settings, load_settings

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


def _base_copy(tmp_path: Path) -> Path:
    base = tmp_path / "default.yaml"
    base.write_text(DEFAULT.read_text(encoding="utf-8"), encoding="utf-8")
    return base


def _load_with(monkeypatch: pytest.MonkeyPatch, base: Path, profile: str | None) -> Settings:
    # Environment only, through monkeypatch, so nothing leaks into later tests.
    monkeypatch.setenv("LH_CONFIG", str(base))
    if profile is None:
        monkeypatch.delenv("LH_PROFILE", raising=False)
    else:
        monkeypatch.setenv("LH_PROFILE", profile)
    return Settings()


def test_profile_overlays_only_what_it_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _base_copy(tmp_path)
    (tmp_path / "aws.yaml").write_text("scoring:\n  alert_threshold: 0.9\n", encoding="utf-8")
    monkeypatch.delenv("LH_SCORING__ALERT_THRESHOLD", raising=False)
    overlaid = _load_with(monkeypatch, base, "aws")
    plain = _load_with(monkeypatch, base, None)
    assert overlaid.scoring.alert_threshold == 0.9
    assert overlaid.scoring.store_floor == plain.scoring.store_floor
    assert {b.name for b in overlaid.brands} == {b.name for b in plain.brands}


def test_no_profile_leaves_base_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = _base_copy(tmp_path)
    (tmp_path / "aws.yaml").write_text("db_path: /elsewhere.duckdb\n", encoding="utf-8")
    assert _load_with(monkeypatch, base, None).db_path == Path("data/lookalike.duckdb")


@pytest.mark.parametrize("name", ["../secrets", "a/b", "AWS"])
def test_profile_name_must_be_plain(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _base_copy(tmp_path)
    with pytest.raises(ValueError, match="plain name"):
        _load_with(monkeypatch, base, name)


def test_missing_profile_file_fails_loudly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = _base_copy(tmp_path)
    with pytest.raises(FileNotFoundError, match="nope"):
        _load_with(monkeypatch, base, "nope")


def test_aws_profile_loads_and_keeps_the_brands(monkeypatch: pytest.MonkeyPatch) -> None:
    aws = _load_with(monkeypatch, DEFAULT, "aws")
    base = _load_with(monkeypatch, DEFAULT, None)
    assert aws.db_path == Path("/var/lib/lookalike-hunter/lookalike.duckdb")
    assert aws.classify.backend == "mistral"
    assert {b.name for b in aws.brands} == {b.name for b in base.brands}
    assert aws.scoring.alert_threshold == base.scoring.alert_threshold
