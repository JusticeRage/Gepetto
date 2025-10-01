import configparser
import gettext
import os

import ida_settings

from gepetto.models.model_manager import instantiate_model, load_available_models, get_fallback_model

# =============================================================================
# Global Fields
# =============================================================================

# Active language model instance for processing requests
model = None

# INI configuration file parser object
parsed_ini = None

# Translator function for message localization
_translator = None

# Current localization language, loaded from configuration file
language = None

# Available locales, loaded from the locales directory
available_locales = None

# =============================================================================


def _stringify_config_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


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
    global model, parsed_ini, _translator, language, available_locales
    parsed_ini = configparser.RawConfigParser()
    parsed_ini.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini"), encoding="utf-8")

    # Read available locales from the locales directory
    locales_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "locales")
    available_locales = set()
    if os.path.exists(locales_dir):
        for item in os.listdir(locales_dir):
            item_path = os.path.join(locales_dir, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                available_locales.add(item)

    # Set up translations
    language = parsed_ini.get('Gepetto', 'LANGUAGE')
    translate = gettext.translation('gepetto',
                                    locales_dir,
                                    fallback=True,
                                    languages=[language])
    _translator = translate.gettext

    # Select model
    requested_model = ida_settings.get_current_plugin_setting("model")
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

    # Ensure Gemini section exists - this is a good place to initialize default sections if they don't exist
    if not parsed_ini.has_section("Gemini"):
        parsed_ini.add_section("Gemini")
        # Optionally, set default values here if you want them written to config.ini
        # For example:
        # parsed_ini.set("Gemini", "BASE_URL", "https://generativelanguage.googleapis.com")
        # However, get_config handles defaults, so explicit setting might not be needed unless you want to persist them.

    if not parsed_ini.has_option("Gepetto", "AUTO_SHOW_STATUS_PANEL"):
        parsed_ini.set("Gepetto", "AUTO_SHOW_STATUS_PANEL", "true")


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
        if environment_variable and os.environ.get(environment_variable):
            return os.environ.get(environment_variable)
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
    config.set(section, option, _stringify_config_value(new_value))
    with open(path, "w", encoding="utf-8") as f:
        config.write(f)

    global parsed_ini
    if parsed_ini is not None:
        if not parsed_ini.has_section(section):
            parsed_ini.add_section(section)
        parsed_ini.set(section, option, _stringify_config_value(new_value))


def get_localization_locale():
    """
    Returns a valid language locale. If the current language is not valid,
    returns 'en_US' as the default.
    :return: Valid language locale string
    """
    global language, available_locales
    
    # Check if current language is valid
    if language and language in available_locales:
        return language
    
    # Return default locale if current language is invalid
    return 'en_US'

def auto_show_status_panel_enabled() -> bool:
    global parsed_ini
    if parsed_ini is None:
        load_config()
    try:
        return parsed_ini.getboolean("Gepetto", "AUTO_SHOW_STATUS_PANEL")
    except (configparser.NoOptionError, configparser.NoSectionError, ValueError):
        return True


def set_auto_show_status_panel(enabled: bool) -> None:
    update_config("Gepetto", "AUTO_SHOW_STATUS_PANEL", enabled)
