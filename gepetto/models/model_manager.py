import importlib.util
import os
import pathlib

from gepetto.models.base import LanguageModel

MODEL_LIST: list[LanguageModel] = list()


# Describes where the provider currently being imported came from, for log
# messages. Set by the loaders below around each import.
_current_source = "built-in"


def register_model(model: LanguageModel):
    if not isinstance(model, type) or not issubclass(model, LanguageModel):
        return
    # Checked before the collision scan on purpose: an unconfigured provider
    # must never displace a working one and leave the user with nothing.
    try:
        if not model.is_configured_properly():
            return
    except Exception as e:
        print(f"Gepetto: provider {model!r} failed its configuration check: {e!r}")
        return

    menu_name = model.get_menu_name()
    for index, existing in enumerate(MODEL_LIST):
        if existing.get_menu_name() != menu_name:
            continue
        if existing is model:
            return
        MODEL_LIST[index] = model
        print(f"Gepetto: provider '{menu_name}' overridden by {_current_source}")
        return
    MODEL_LIST.append(model)


def list_models():
    return MODEL_LIST


def instantiate_model(model):
    """
    Instantiates a model based on its name
    :param model: The model to use
    :return:
    """
    for m in MODEL_LIST:
        available = m.supported_models()
        if model in available:
            return m(model)
        refresher = getattr(m, "refresh_models_sync", None)
        if callable(refresher):
            try:
                refreshed = refresher()
            except Exception:
                continue
            if model in (refreshed or []):
                return m(model)
    raise RuntimeError(f"{model} does not exist!")


def get_fallback_model():
    """
    This function returns the first model that can be instantiated properly.
    :return:
    """
    for model_plugin in MODEL_LIST:
        available = model_plugin.supported_models()
        for m in available:
            try:
                return model_plugin(m)
            except:
                continue
    raise RuntimeError(
        "No models available! Edit your configuration file and try again."
    )


def load_available_models():
    folder = pathlib.Path(os.path.dirname(__file__))
    for py_file in folder.glob("*.py"):
        module_name = py_file.stem  # Get the file name without extension
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except (ImportError, ModuleNotFoundError) as e:
            print("Module", module_name, "loading failed:", repr(e), "Skipping..")
