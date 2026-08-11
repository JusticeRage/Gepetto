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
