"""A missing optional dependency is the normal state, not a defect.

Someone who does not use Claude will never install the anthropic SDK. Printing
a full traceback for each such provider on every IDA start buries the messages
that matter, so those get one line while genuine defects keep their traceback.
"""

import pytest

import gepetto.models.model_manager as model_manager


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setattr(model_manager, "MODEL_LIST", [])
    monkeypatch.setattr(model_manager, "_LOADED_FILES", {})
    monkeypatch.setattr(model_manager, "_current_source", "built-in")


def write(folder, name, body):
    # folder is pytest's tmp_path: it already exists, is unique per test, and
    # pytest removes it once it is a few sessions old.
    (folder / name).write_text(body, encoding="utf-8")


def test_a_missing_sdk_reports_one_line_and_no_traceback(tmp_path, capsys):
    write(tmp_path, "needs_sdk.py", "import a_package_that_is_not_installed\n")

    model_manager._load_directory(tmp_path, "built-in")

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Traceback" not in output, output
    assert output.count("\n") == 1, f"expected a single line, got:\n{output}"
    assert "needs_sdk" in output
    assert "a_package_that_is_not_installed" in output


def test_a_partial_import_counts_as_a_missing_dependency(tmp_path, capsys):
    # 'from google import genai' raises ImportError, not ModuleNotFoundError.
    write(tmp_path, "partial.py", "from json import not_a_real_name\n")

    model_manager._load_directory(tmp_path, "built-in")

    output = capsys.readouterr().out
    assert "Traceback" not in output
    assert "optional dependency missing" in output


def test_a_real_defect_keeps_its_traceback(tmp_path, capsys):
    write(tmp_path, "broken.py", "raise RuntimeError('boom')\n")

    model_manager._load_directory(tmp_path, "built-in")

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Traceback" in output, output
    assert "boom" in output


def test_a_syntax_error_keeps_its_traceback(tmp_path, capsys):
    write(tmp_path, "syntax.py", "def broken(:\n")

    model_manager._load_directory(tmp_path, "built-in")

    # One readouterr() call: it drains the buffer, so a second returns empty.
    captured = capsys.readouterr()
    assert "Traceback" in captured.out + captured.err


def test_one_unavailable_provider_does_not_stop_the_others(tmp_path, capsys):
    write(tmp_path, "a_missing.py", "import still_not_installed\n")
    write(
        tmp_path,
        "b_working.py",
        "from gepetto.models.base import LanguageModel\n"
        "import gepetto.models.model_manager\n"
        "class P(LanguageModel):\n"
        "    @staticmethod\n"
        "    def get_menu_name(): return 'Works'\n"
        "    @staticmethod\n"
        "    def supported_models(): return ['m']\n"
        "    @staticmethod\n"
        "    def is_configured_properly(): return True\n"
        "    def query_model_async(self, query, cb, stream, additional_model_options): ...\n"
        "gepetto.models.model_manager.register_model(P)\n",
    )

    model_manager._load_directory(tmp_path, "built-in")

    assert [p.get_menu_name() for p in model_manager.MODEL_LIST] == ["Works"]
    assert "Traceback" not in capsys.readouterr().out


def test_the_real_providers_never_produce_a_traceback(capsys):
    """Whatever SDKs this environment has, absent ones must stay quiet."""
    import gepetto.paths

    model_manager._load_directory(
        gepetto.paths.PLUGIN_DIR / "models", "built-in", package="gepetto.models"
    )

    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
