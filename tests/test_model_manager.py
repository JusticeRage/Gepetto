import textwrap

import pytest

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager as model_manager


def make_provider(menu_name, configured=True, models=("m1",)):
    class Provider(LanguageModel):
        @staticmethod
        def get_menu_name():
            return menu_name

        @staticmethod
        def supported_models():
            return list(models)

        @staticmethod
        def is_configured_properly():
            return configured

        def query_model_async(self, query, cb, stream, additional_model_options):
            raise NotImplementedError

    return Provider


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    monkeypatch.setattr(model_manager, "MODEL_LIST", [])
    monkeypatch.setattr(model_manager, "_current_source", "built-in")


def test_registers_a_configured_provider():
    provider = make_provider("Alpha")
    model_manager.register_model(provider)
    assert model_manager.MODEL_LIST == [provider]


def test_ignores_an_unconfigured_provider():
    model_manager.register_model(make_provider("Alpha", configured=False))
    assert model_manager.MODEL_LIST == []


def test_ignores_a_non_language_model():
    model_manager.register_model(object)
    model_manager.register_model("not even a class")
    assert model_manager.MODEL_LIST == []


def test_later_registration_replaces_the_earlier_one(capsys):
    first = make_provider("Alpha")
    second = make_provider("Alpha")

    model_manager.register_model(first)
    model_manager._current_source = "user (drop-in.py)"
    model_manager.register_model(second)

    assert model_manager.MODEL_LIST == [second]
    assert "overridden by user (drop-in.py)" in capsys.readouterr().out


def test_unconfigured_provider_does_not_displace_a_working_one():
    first = make_provider("Alpha")
    model_manager.register_model(first)
    model_manager.register_model(make_provider("Alpha", configured=False))
    assert model_manager.MODEL_LIST == [first]


def test_registering_the_same_class_twice_is_a_no_op(capsys):
    provider = make_provider("Alpha")
    model_manager.register_model(provider)
    model_manager.register_model(provider)
    assert model_manager.MODEL_LIST == [provider]
    assert "overridden" not in capsys.readouterr().out


def test_override_does_not_disturb_other_providers():
    alpha, beta, alpha2 = make_provider("Alpha"), make_provider("Beta"), make_provider("Alpha")
    model_manager.register_model(alpha)
    model_manager.register_model(beta)
    model_manager.register_model(alpha2)
    assert model_manager.MODEL_LIST == [alpha2, beta]


PROVIDER_TEMPLATE = """
    from gepetto.models.base import LanguageModel
    import gepetto.models.model_manager


    class Provider(LanguageModel):
        @staticmethod
        def get_menu_name():
            return "{menu_name}"

        @staticmethod
        def supported_models():
            return ["{menu_name}-model"]

        @staticmethod
        def is_configured_properly():
            return {configured}

        def query_model_async(self, query, cb, stream, additional_model_options):
            raise NotImplementedError


    gepetto.models.model_manager.register_model(Provider)
"""


def write_provider(folder, filename, menu_name, configured=True):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / filename).write_text(
        textwrap.dedent(PROVIDER_TEMPLATE).format(menu_name=menu_name, configured=configured),
        encoding="utf-8",
    )


def test_directory_scan_registers_a_drop_in_provider(tmp_path):
    write_provider(tmp_path, "mine.py", "Mine")
    model_manager._load_directory(tmp_path, "user")
    assert [p.get_menu_name() for p in model_manager.MODEL_LIST] == ["Mine"]


def test_directory_scan_skips_dunder_and_private_files(tmp_path):
    write_provider(tmp_path, "__init__.py", "Dunder")
    write_provider(tmp_path, "_helper.py", "Private")
    write_provider(tmp_path, "real.py", "Real")
    model_manager._load_directory(tmp_path, "user")
    assert [p.get_menu_name() for p in model_manager.MODEL_LIST] == ["Real"]


def test_a_broken_provider_does_not_abort_the_scan(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    write_provider(tmp_path, "working.py", "Working")

    model_manager._load_directory(tmp_path, "user")

    assert [p.get_menu_name() for p in model_manager.MODEL_LIST] == ["Working"]
    captured = capsys.readouterr()
    assert "broken.py" in captured.out + captured.err


def test_missing_directory_is_not_an_error(tmp_path):
    model_manager._load_directory(tmp_path / "does-not-exist", "user")
    assert model_manager.MODEL_LIST == []


def test_drop_in_overrides_a_previously_registered_provider(tmp_path, capsys):
    builtin = make_provider("Shared")
    model_manager.register_model(builtin)

    write_provider(tmp_path, "shared.py", "Shared")
    model_manager._load_directory(tmp_path, "user")

    assert model_manager.MODEL_LIST[0] is not builtin
    assert "overridden by user" in capsys.readouterr().out


class FakeEntryPoint:
    def __init__(self, name, value, target):
        self.name = name
        self.value = value
        self._target = target

    def load(self):
        if isinstance(self._target, Exception):
            raise self._target
        return self._target


def patch_entry_points(monkeypatch, entry_points):
    def _entry_points(group=None):
        assert group == "gepetto.providers"
        return list(entry_points)

    monkeypatch.setattr(model_manager.importlib.metadata, "entry_points", _entry_points)


def test_entry_point_exposing_a_class_is_registered(monkeypatch):
    provider = make_provider("FromClass")
    patch_entry_points(monkeypatch, [FakeEntryPoint("c", "pkg:Provider", provider)])

    model_manager._load_entry_points()

    assert model_manager.MODEL_LIST == [provider]


def test_entry_point_exposing_a_callable_receives_the_registrar(monkeypatch):
    first, second = make_provider("One"), make_provider("Two")

    def register_all(register):
        register(first)
        register(second)

    patch_entry_points(monkeypatch, [FakeEntryPoint("h", "pkg:register_all", register_all)])

    model_manager._load_entry_points()

    assert model_manager.MODEL_LIST == [first, second]


def test_a_broken_entry_point_does_not_abort_the_others(monkeypatch, capsys):
    working = make_provider("Working")
    patch_entry_points(monkeypatch, [
        FakeEntryPoint("bad", "pkg:missing", ImportError("no such module")),
        FakeEntryPoint("good", "pkg:Provider", working),
    ])

    model_manager._load_entry_points()

    assert model_manager.MODEL_LIST == [working]
    assert "bad" in capsys.readouterr().out


def test_entry_point_overrides_a_drop_in(monkeypatch, tmp_path, capsys):
    write_provider(tmp_path, "shared.py", "Shared")
    model_manager._load_directory(tmp_path, "user")
    from_drop_in = model_manager.MODEL_LIST[0]

    patch_entry_points(monkeypatch, [FakeEntryPoint("e", "pkg:Provider", make_provider("Shared"))])
    model_manager._load_entry_points()

    assert model_manager.MODEL_LIST[0] is not from_drop_in
    assert "overridden by entry point e" in capsys.readouterr().out
