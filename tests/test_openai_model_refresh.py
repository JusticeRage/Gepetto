"""Regression test for the double `GET /v1/models` fetch on IDA startup.

Two independent code paths used to reach the OpenAI provider's live model
list on every startup:

* ``GPT.supported_models()`` (called by ``instantiate_model()`` and by the
  model-select menu construction in ``gepetto/ida/ui.py``) schedules a
  de-duplicated, cooldown-gated background refresh via
  ``_schedule_openai_refresh()``.
* ``instantiate_model()``'s fallback -- reached whenever the configured
  MODEL isn't in the cache yet, which is exactly the case for any model
  that only exists in the live list -- called ``GPT.refresh_models_sync()``,
  which fired its own independent, synchronous HTTP request without
  consulting ``_OPENAI_LAST_REFRESH``/``_OPENAI_REFRESH_THREAD`` at all.

The two requests raced each other from two different threads, producing the
"two identical GET requests, 31ms apart" seen on startup.
"""

import importlib
import textwrap
import threading
import time

import pytest


@pytest.fixture()
def openai_refresh_env(tmp_path, monkeypatch):
    """Loads a real config with a MODEL that only exists in the live list."""

    plugin_dir = tmp_path / "plugin"
    (plugin_dir / "locales" / "en_US" / "LC_MESSAGES").mkdir(parents=True)
    user_dir = tmp_path / "user"

    (plugin_dir / "config.ini").write_text(
        textwrap.dedent(
            """
            [Gepetto]
            MODEL = gpt-5.2-codex-preview
            LANGUAGE = en_US
            AUTO_SHOW_STATUS_PANEL = false

            [OpenAI]
            API_KEY = sk-test-key-not-real
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    import gepetto.config as config
    import gepetto.paths as paths
    import gepetto.models.model_manager as model_manager
    import gepetto.models.openai as openai_mod

    config = importlib.reload(config)

    monkeypatch.setattr(paths, "PLUGIN_DIR", plugin_dir)
    monkeypatch.setenv("GEPETTO_CONFIG_DIR", str(user_dir))

    # Fresh module-level cache, like a brand new IDA process.
    monkeypatch.setattr(openai_mod, "_OPENAI_MODELS", None)
    monkeypatch.setattr(openai_mod, "_OPENAI_LAST_REFRESH", 0.0)
    monkeypatch.setattr(openai_mod, "_OPENAI_REFRESH_THREAD", None)

    monkeypatch.setattr(model_manager, "MODEL_LIST", [])
    monkeypatch.setattr(model_manager, "_LOADED_FILES", {})
    # gepetto.models.openai is already imported (other tests import it), so
    # load_available_models()'s directory scan would just hit sys.modules and
    # skip re-running register_model(GPT). Register it directly instead, the
    # same way a fresh interpreter loading the module for the first time
    # would.
    monkeypatch.setattr(
        config, "load_available_models", lambda: model_manager.register_model(openai_mod.GPT)
    )

    return config, model_manager, openai_mod


def test_openai_models_are_fetched_once_across_load_and_menu_populate(openai_refresh_env, monkeypatch):
    config, model_manager, openai_mod = openai_refresh_env

    calls = []
    calls_lock = threading.Lock()

    def fake_execute_fetch(endpoint, headers, proxy, timeout):
        with calls_lock:
            calls.append(threading.current_thread().name)
        # A little latency, like a real network round trip, so a would-be
        # second fetch has time to race the first instead of trivially
        # losing to it.
        time.sleep(0.05)
        return ["gpt-4o", "gpt-4.1", "gpt-5.2-codex-preview"]

    monkeypatch.setattr(openai_mod, "_execute_openai_fetch", fake_execute_fetch)

    # Step 1: plugin startup -- gepetto.py's PLUGIN_ENTRY() calls this.
    config.load_config()

    # The requested model only exists in the live list, not in
    # _DEFAULT_OPENAI_MODELS, so this also proves instantiate_model() still
    # finds it via the live fetch.
    assert str(config.model) == "gpt-5.2-codex-preview"

    # Step 2: model-select menu construction, mirroring
    # GepettoPlugin.detach_actions() followed by the menu-build loop in
    # generate_model_select_menu() (gepetto/ida/ui.py) -- both iterate every
    # registered provider and call supported_models().
    for provider in model_manager.list_models():
        provider.supported_models()
    for provider in model_manager.list_models():
        for _model in provider.supported_models():
            pass

    # Let any background refresh thread finish before counting.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        with openai_mod._OPENAI_MODELS_LOCK:
            thread = openai_mod._OPENAI_REFRESH_THREAD
        if not thread or not thread.is_alive():
            break
        time.sleep(0.01)

    assert len(calls) == 1, f"expected exactly one /v1/models fetch, got {calls}"


def test_refresh_models_sync_reuses_an_in_flight_supported_models_fetch(openai_refresh_env, monkeypatch):
    """Narrower unit test of the same fix, without going through load_config().

    supported_models() schedules a background fetch; refresh_models_sync()
    called immediately afterwards (as instantiate_model() does when the
    requested model isn't cached yet) must join that fetch instead of
    starting its own.
    """
    config, model_manager, openai_mod = openai_refresh_env

    calls = []
    calls_lock = threading.Lock()

    def fake_execute_fetch(endpoint, headers, proxy, timeout):
        with calls_lock:
            calls.append(threading.current_thread().name)
        time.sleep(0.05)
        return ["gpt-4o", "gpt-5.2-codex-preview"]

    monkeypatch.setattr(openai_mod, "_execute_openai_fetch", fake_execute_fetch)
    # supported_models()/refresh_models_sync() both read the API key straight
    # from gepetto.config.get_config(); load_config() isn't involved in this
    # test, so provide the key via the environment fallback it also checks.
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-not-real")

    openai_mod.GPT.supported_models()
    refreshed = openai_mod.GPT.refresh_models_sync()

    assert "gpt-5.2-codex-preview" in refreshed
    assert len(calls) == 1, f"expected exactly one /v1/models fetch, got {calls}"
