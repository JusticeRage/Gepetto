import importlib.util
import os
import pathlib

from gepetto.models.base import LanguageModel

MODEL_LIST: list[LanguageModel] = list()
FALLBACK_MODEL = "gpt-4o"

def register_model(model: LanguageModel):
    if not issubclass(model, LanguageModel):
        return
    if any(existing.get_menu_name() == model.get_menu_name() for existing in MODEL_LIST):
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
    # If nothing was found, use the default model.
    print(f"Warning:  {model} does not exist! Using default model ({FALLBACK_MODEL}).")
    return instantiate_model(FALLBACK_MODEL)

def load_available_models():
    folder = pathlib.Path(os.path.dirname(__file__))
    for py_file in folder.glob("*.py"):
        module_name = py_file.stem  # Get the file name without extension
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
