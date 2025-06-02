import configparser
import gettext
import os

from gepetto.models.model_manager import instantiate_model, load_available_models, get_fallback_model

model = None
parsed_ini = None
_translator = None


def _get_translator():
    global _translator
    if _translator is None:
        load_config()

    return _translator


def _(message):
    """Translation function that lazy-loads the translator"""
    return _get_translator()(message)


def load_config():
    """
    Loads the configuration of the plugin from the INI file. Sets up the correct locale and language model.
    Also prepares an OpenAI client configured accordingly to the user specifications.
    :return:
    """
    global model, parsed_ini, _translator
    parsed_ini = configparser.RawConfigParser()
    parsed_ini.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini"), encoding="utf-8")

    # Set up translations
    language = parsed_ini.get('Gepetto', 'LANGUAGE')
    translate = gettext.translation('gepetto',
                                    os.path.join(os.path.abspath(os.path.dirname(__file__)), "locales"),
                                    fallback=True,
                                    languages=[language])
    _translator = translate.gettext

    # Select model
    requested_model = parsed_ini.get('Gepetto', 'MODEL')
    load_available_models()
    # Attempt to load the requested model, otherwise get the first available one, or don't load Gepetto
    try:
        model = instantiate_model(requested_model)
    except RuntimeError:
        print(_("Attempting to load the first available model..."))
        try:
            model = get_fallback_model()
            print(f"Defaulted to {str(model)}.")
        except RuntimeError:
            print(_("No model available. Please edit the configuration file and try again."))
            model = None


def get_config(section, option, environment_variable=None, default=None):
    """
    Returns a value from the configuration, by looking successively in the configuration file and the environment
    variables, returning the default value provided if nothing can be found.
    :param section: The section containing the option.
    :param option: The requested option.
    :param environment_variable: The environment variable possibly containing the value.
    :param default: Default value to return if nothing can be found.
    :return: The value of the requested option.
    """
    global parsed_ini
    try:
        if parsed_ini and parsed_ini.get(section, option):
            return parsed_ini.get(section, option)
        if environment_variable is not None:
            if isinstance(environment_variable, (str)):
                environment_variable = [environment_variable]
            for env_var in environment_variable:
                if os.environ.get(env_var):
                    return os.environ.get(env_var)
    except (configparser.NoSectionError, configparser.NoOptionError):
        print(_("Warning: Gepetto's configuration doesn't contain option {option} in section {section}!").format(
            option=option,
            section=section
        ))
    return default


def update_config(section, option, new_value):
    """
    Updates a single entry in the configuration.
    :param section: The section in which the option is located
    :param option: The option to update
    :param new_value: The new value to set
    :return:
    """
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini")
    config = configparser.RawConfigParser()
    config.read(path, encoding="utf-8")
    config.set(section, option, new_value)
    with open(path, "w", encoding="utf-8") as f:
        config.write(f)