import configparser
import importlib
import textwrap

import pytest


@pytest.fixture()
def config_env(tmp_path, monkeypatch):
    """Isolate plugin-relative assets and the user config directory separately."""

    plugin_dir = tmp_path / "plugin"
    (plugin_dir / "locales" / "en_US" / "LC_MESSAGES").mkdir(parents=True)
    user_dir = tmp_path / "user"

    def write_bundled(content: str):
        (plugin_dir / "config.ini").write_text(
            textwrap.dedent(content).strip() + "\n",
            encoding="utf-8",
        )

    write_bundled(
        """
        [Gepetto]
        MODEL = gpt-4
        LANGUAGE = en_US
        AUTO_SHOW_STATUS_PANEL = true

        [OpenAI]
        API_KEY =
        """
    )

    import gepetto.config as config
    import gepetto.paths as paths

    config = importlib.reload(config)

    monkeypatch.setattr(paths, "PLUGIN_DIR", plugin_dir)
    monkeypatch.setenv("GEPETTO_CONFIG_DIR", str(user_dir))

    return config, write_bundled, plugin_dir, user_dir


@pytest.fixture()
def loaded_config(config_env, monkeypatch):
    """Return a loaded config module with standard model stubs applied."""

    config, write_bundled, plugin_dir, user_dir = config_env

    sentinel_model = object()

    monkeypatch.setattr(config, "load_available_models", lambda: None)
    monkeypatch.setattr(config, "instantiate_model", lambda _: sentinel_model)
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    config.load_config()

    return config, write_bundled, plugin_dir, user_dir


def test_load_config_successfully_initializes_environment(config_env, monkeypatch):
    config, _, _, _ = config_env

    sentinel_model = object()
    load_calls = []

    monkeypatch.setattr(config, "load_available_models", lambda: load_calls.append("called"))
    monkeypatch.setattr(config, "instantiate_model", lambda model_name: sentinel_model)
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    config.load_config()

    assert config.model is sentinel_model
    assert config.parsed_ini.get("Gepetto", "MODEL") == "gpt-4"
    assert config.language == "en_US"
    assert config.available_locales == {"en_US"}
    assert config.parsed_ini.get("Gepetto", "AUTO_SHOW_STATUS_PANEL") == "true"
    assert load_calls == ["called"]


def test_load_config_uses_fallback_model_when_requested_model_fails(config_env, monkeypatch, capsys):
    config, _, _, _ = config_env

    fallback_model = object()

    monkeypatch.setattr(config, "load_available_models", lambda: None)

    def _raise(_: str):
        raise RuntimeError("boom")

    monkeypatch.setattr(config, "instantiate_model", _raise)
    monkeypatch.setattr(config, "get_fallback_model", lambda: fallback_model)

    config.load_config()

    captured = capsys.readouterr()
    assert "Attempting to load the first available model" in captured.out
    assert "Defaulted to" in captured.out
    assert config.model is fallback_model


def test_load_config_gracefully_handles_missing_models(config_env, monkeypatch, capsys):
    config, _, _, _ = config_env

    monkeypatch.setattr(config, "load_available_models", lambda: None)

    def _raise(_: str):
        raise RuntimeError("boom")

    monkeypatch.setattr(config, "instantiate_model", _raise)

    def _raise_fallback():
        raise RuntimeError("no models")

    monkeypatch.setattr(config, "get_fallback_model", _raise_fallback)

    config.load_config()

    captured = capsys.readouterr()
    assert "No model available" in captured.out
    assert config.model is None


def test_get_config_prefers_configuration_value(loaded_config):
    config, _, _, _ = loaded_config

    value = config.get_config("Gepetto", "MODEL", environment_variable="MODEL_ENV", default="default")
    assert value == "gpt-4"


def test_get_config_uses_environment_variable_when_config_empty(config_env, monkeypatch):
    config, write_bundled, _, _ = config_env

    write_bundled(
        """
        [Gepetto]
        MODEL = gpt-4
        LANGUAGE = en_US
        AUTO_SHOW_STATUS_PANEL = true

        [OpenAI]
        API_KEY =
        """
    )

    monkeypatch.setattr(config, "load_available_models", lambda: None)
    monkeypatch.setattr(config, "instantiate_model", lambda _: object())
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    monkeypatch.setenv("OPENAI_API_KEY", "secret")

    config.load_config()

    value = config.get_config("OpenAI", "API_KEY", environment_variable="OPENAI_API_KEY", default="default")
    assert value == "secret"


def test_get_config_returns_default_when_missing(loaded_config):
    config, _, _, _ = loaded_config

    value = config.get_config("Missing", "Option", default="fallback")
    assert value == "fallback"


def test_update_config_updates_file_and_cache(loaded_config):
    config, _, plugin_dir, user_dir = loaded_config

    config.update_config("Gepetto", "MODEL", "gpt-3.5")

    assert config.parsed_ini.get("Gepetto", "MODEL") == "gpt-3.5"
    file_config = configparser.RawConfigParser()
    file_config.read(user_dir / "config.ini", encoding="utf-8")
    assert file_config.get("Gepetto", "MODEL") == "gpt-3.5"

    # The bundled template must never be written to.
    bundled = configparser.RawConfigParser()
    bundled.read(plugin_dir / "config.ini", encoding="utf-8")
    assert bundled.get("Gepetto", "MODEL") == "gpt-4"


def test_get_localization_locale_returns_valid_language(loaded_config):
    config, _, _, _ = loaded_config

    assert config.get_localization_locale() == "en_US"


def test_get_localization_locale_returns_default_for_invalid_language(loaded_config):
    config, _, _, _ = loaded_config
    config.language = "fr_FR"

    assert config.get_localization_locale() == "en_US"


def test_first_run_seeds_the_user_config_from_the_bundled_file(config_env, monkeypatch, capsys):
    # Deliberately not the loaded_config fixture: load_config() has to run
    # inside the test body for capsys to see the migration message.
    config, _, plugin_dir, user_dir = config_env

    monkeypatch.setattr(config, "load_available_models", lambda: None)
    monkeypatch.setattr(config, "instantiate_model", lambda _: object())
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    assert not (user_dir / "config.ini").exists()

    config.load_config()

    user_cfg = user_dir / "config.ini"
    assert user_cfg.exists()
    assert user_cfg.read_text(encoding="utf-8") == (plugin_dir / "config.ini").read_text(encoding="utf-8")
    assert config.config_path == user_cfg
    assert "migrated" in capsys.readouterr().out


def test_first_run_makes_the_user_config_private(loaded_config):
    import os
    import stat

    config, _, _, user_dir = loaded_config

    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    mode = stat.S_IMODE((user_dir / "config.ini").stat().st_mode)
    assert mode == 0o600


def test_existing_user_config_is_not_overwritten(config_env, monkeypatch):
    config, _, _, user_dir = config_env

    user_dir.mkdir(parents=True)
    (user_dir / "config.ini").write_text(
        "[Gepetto]\nMODEL = already-mine\nLANGUAGE = en_US\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(config, "load_available_models", lambda: None)
    monkeypatch.setattr(config, "instantiate_model", lambda _: object())
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    config.load_config()

    assert config.parsed_ini.get("Gepetto", "MODEL") == "already-mine"


def test_missing_config_everywhere_still_loads(config_env, monkeypatch, capsys):
    config, _, plugin_dir, _ = config_env

    (plugin_dir / "config.ini").unlink()

    monkeypatch.setattr(config, "load_available_models", lambda: None)
    monkeypatch.setattr(config, "instantiate_model", lambda _: object())
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    config.load_config()

    assert config.parsed_ini.has_section("Gepetto")
    assert config.get_config("Gepetto", "MODEL", default="fallback") == "fallback"


def test_unwritable_user_directory_falls_back_to_the_bundled_file(config_env, monkeypatch, capsys):
    config, _, plugin_dir, user_dir = config_env

    def _explode(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(config.pathlib.Path, "mkdir", _explode)
    monkeypatch.setattr(config, "load_available_models", lambda: None)
    monkeypatch.setattr(config, "instantiate_model", lambda _: object())
    monkeypatch.setattr(config, "get_fallback_model", lambda: None)

    config.load_config()

    assert config.config_path == plugin_dir / "config.ini"
    assert config.parsed_ini.get("Gepetto", "MODEL") == "gpt-4"
    assert "falling back" in capsys.readouterr().out
