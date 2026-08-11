import os
from pathlib import Path

import pytest

import gepetto.paths as paths


def test_explicit_override_wins_and_is_used_verbatim(tmp_path, monkeypatch):
    monkeypatch.setenv("GEPETTO_CONFIG_DIR", str(tmp_path / "explicit"))
    assert paths.user_dir() == tmp_path / "explicit"


def test_ida_user_dir_is_preferred_over_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("GEPETTO_CONFIG_DIR", raising=False)
    monkeypatch.setenv("IDAUSR", str(tmp_path / "from_env"))
    monkeypatch.setattr(paths, "_ida_user_dir", lambda: tmp_path / "from_ida")
    assert paths.user_dir() == tmp_path / "from_ida" / "cfg" / "gepetto"


def test_falls_back_to_idausr_when_ida_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("GEPETTO_CONFIG_DIR", raising=False)
    monkeypatch.setenv("IDAUSR", str(tmp_path / "from_env"))
    monkeypatch.setattr(paths, "_ida_user_dir", lambda: None)
    assert paths.user_dir() == tmp_path / "from_env" / "cfg" / "gepetto"


def test_idausr_list_takes_only_the_first_entry(tmp_path, monkeypatch):
    monkeypatch.delenv("GEPETTO_CONFIG_DIR", raising=False)
    separator = ";" if os.name == "nt" else ":"
    monkeypatch.setenv("IDAUSR", separator.join([str(tmp_path / "first"), str(tmp_path / "second")]))
    monkeypatch.setattr(paths, "_ida_user_dir", lambda: None)
    assert paths.user_dir() == tmp_path / "first" / "cfg" / "gepetto"


def test_falls_back_to_home_when_nothing_is_set(monkeypatch):
    monkeypatch.delenv("GEPETTO_CONFIG_DIR", raising=False)
    monkeypatch.delenv("IDAUSR", raising=False)
    monkeypatch.setattr(paths, "_ida_user_dir", lambda: None)
    assert paths.user_dir() == Path.home() / ".idapro" / "cfg" / "gepetto"


def test_derived_paths_hang_off_user_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GEPETTO_CONFIG_DIR", str(tmp_path))
    assert paths.config_file() == tmp_path / "config.ini"
    assert paths.providers_dir() == tmp_path / "providers"


def test_plugin_relative_paths_do_not_move(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "PLUGIN_DIR", tmp_path)
    assert paths.bundled_config() == tmp_path / "config.ini"
    assert paths.locales_dir() == tmp_path / "locales"


def test_ida_user_dir_reports_the_real_directory_under_ida():
    # idalib requires `import idapro` before any other ida_* module; conftest
    # already did that, so this exercises the real lookup.
    resolved = paths._ida_user_dir()
    assert resolved is not None
    assert resolved.is_dir()
