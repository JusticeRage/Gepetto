import importlib.util
import os
import pathlib

from gepetto.models.base import LanguageModel

MODEL_LIST: list[LanguageModel] = list()

def register_model(model: LanguageModel):
    if not issubclass(model, LanguageModel):
        return
    if any(existing.get_menu_name() == model.get_menu_name() for existing in MODEL_LIST):
        return
    if not model.is_configured_properly():
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
        if model in m.supported_models():
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
    raise RuntimeError("No models available! Edit your configuration file and try again.")

def load_available_models():
    folder = pathlib.Path(os.path.dirname(__file__))
    for py_file in folder.glob("*.py"):
        module_name = py_file.stem  # Get the file name without extension
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
