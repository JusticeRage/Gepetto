import importlib.metadata
import importlib.util
import pathlib
import traceback

import gepetto.paths
from gepetto.models.base import LanguageModel

MODEL_LIST: list[LanguageModel] = list()


def _missing_dependency(exc):
    """Name the dependency an import failure was looking for."""
    # 'from google import genai' raises ImportError rather than
    # ModuleNotFoundError, and reports the outer package as its name.
    return getattr(exc, "name", None) or str(exc)


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


# Drop-in files already executed, keyed by resolved path, so that calling
# load_available_models() twice does not re-execute them and re-register a
# second, identical-but-distinct class over the first.
_LOADED_FILES = {}


def _load_directory(folder, source: str, package: str = None):
    """Import every provider module in a directory.

    ``package`` names the Python package the directory corresponds to, and is
    set for the built-in models. Importing those normally rather than by file
    path matters: the built-ins import each other (``from gepetto.models.openai
    import GPT``), so loading them by path as well would build a second, distinct
    copy of every class and register it over the first.

    Failures are contained per file: these modules may be third-party, and an
    exception here would otherwise escape load_config() and PLUGIN_ENTRY(),
    taking the whole plugin down instead of one provider.
    """
    global _current_source
    folder = pathlib.Path(folder)
    if not folder.is_dir():
        return

    for py_file in sorted(folder.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        resolved = str(py_file.resolve())
        if resolved in _LOADED_FILES:
            continue
        _current_source = f"{source} ({py_file})"
        try:
            if package:
                importlib.import_module(f"{package}.{py_file.stem}")
            else:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            _LOADED_FILES[resolved] = True
        except (ImportError, ModuleNotFoundError) as e:
            # Expected, not a defect: someone who does not use Claude will never
            # have the anthropic SDK installed. One line, no stack trace.
            print(
                f"Gepetto: provider '{py_file.stem}' unavailable, optional "
                f"dependency missing: {_missing_dependency(e)}"
            )
        except Exception:
            # A syntax error or an exception raised by the module itself. This
            # is a real defect and the traceback is the point.
            print(f"Gepetto: failed to load provider {py_file}:")
            traceback.print_exc()

    _current_source = "built-in"


def _load_entry_points(group: str = "gepetto.providers"):
    """Import providers advertised by installed distributions.

    An entry point may resolve to a LanguageModel subclass, or to a callable
    that is handed register_model so one distribution can register several.
    """
    global _current_source
    try:
        discovered = importlib.metadata.entry_points(group=group)
    except Exception:
        print(f"Gepetto: could not enumerate '{group}' entry points:")
        traceback.print_exc()
        return

    for entry_point in discovered:
        _current_source = f"entry point {entry_point.name} ({getattr(entry_point, 'value', '')})"
        try:
            target = entry_point.load()
            if isinstance(target, type):
                register_model(target)
            elif callable(target):
                target(register_model)
            else:
                print(f"Gepetto: entry point {entry_point.name} is neither a class nor callable; ignoring.")
        except (ImportError, ModuleNotFoundError) as e:
            print(
                f"Gepetto: entry point '{entry_point.name}' unavailable, optional "
                f"dependency missing: {_missing_dependency(e)}"
            )
        except Exception:
            print(f"Gepetto: failed to load provider from entry point {entry_point.name}:")
            traceback.print_exc()

    _current_source = "built-in"


def load_available_models():
    _load_directory(gepetto.paths.PLUGIN_DIR / "models", "built-in", package=__package__)
    _load_directory(gepetto.paths.providers_dir(), "user")
    _load_entry_points()
