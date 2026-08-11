import configparser
import gettext
import os
import pathlib
import re
import shutil

import gepetto.paths
from gepetto.models.model_manager import instantiate_model, load_available_models, get_fallback_model

# =============================================================================
# Global Fields
# =============================================================================

# Active language model instance for processing requests
model = None

# INI configuration file parser object
parsed_ini = None

# Path of the configuration file actually in use, set by load_config().
config_path = None

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


_SECTION_RE = re.compile(r"^\s*\[(?P<name>[^]]+)\]\s*$")


def _indent_width(line) -> int:
    return len(line) - len(line.lstrip())


def _is_blank_or_comment(line) -> bool:
    stripped = line.strip()
    return not stripped or stripped[0] in "#;"


def _find_section(lines, section):
    """Return the (start, end) line bounds of a section, or (None, None)."""
    target = section.strip().lower()
    start = None
    for index, line in enumerate(lines):
        match = _SECTION_RE.match(line)
        if not match:
            continue
        if start is None:
            if match.group("name").strip().lower() == target:
                start = index
        else:
            return start, index
    return (start, len(lines)) if start is not None else (None, None)


def _set_option_in_text(text, section, option, value):
    """Set one option in INI text, leaving every other byte alone.

    Reserializing through RawConfigParser would be shorter, but it drops every
    comment in the file. That was tolerable when the config lived in the plugin
    directory and was replaced on each upgrade; now that it is the user's own
    file, switching models from the menu must not delete their annotations.
    """
    lines = text.splitlines(keepends=True)
    start, end = _find_section(lines, section)

    if start is None:
        prefix = text if (not text or text.endswith("\n")) else text + "\n"
        if prefix.strip():
            prefix += "\n"
        return f"{prefix}[{section}]\n{option} = {value}\n"

    # Case-insensitive to match RawConfigParser's own option lookup, and the
    # captured prefix preserves the key's spelling, separator and spacing.
    # Horizontal whitespace only. A plain \s* after the separator swallows the
    # newline when the option is empty ("API_KEY ="), which is the usual state
    # of a freshly installed config, and the value then lands on its own line
    # without its key.
    pattern = re.compile(
        r"^(?P<prefix>[^\S\n]*" + re.escape(option) + r"[^\S\n]*[:=][^\S\n]*)",
        re.IGNORECASE,
    )
    for index in range(start + 1, end):
        if _is_blank_or_comment(lines[index]):
            continue
        match = pattern.match(lines[index])
        if not match:
            continue
        prefix = match.group("prefix")
        if not prefix[-1:].isspace():
            # "API_KEY =" has nothing after the separator. Follow the spacing
            # the file already uses around it rather than jamming the value
            # against the '=', while leaving a compact "KEY=value" compact.
            separator = max(prefix.rfind("="), prefix.rfind(":"))
            if separator > 0 and prefix[separator - 1].isspace():
                prefix += " "
        option_indent = _indent_width(prefix)
        lines[index] = f"{prefix}{value}\n"
        # Drop what remains of a multi-line value. Per configparser, only lines
        # indented further than the key continue it, so options that merely
        # share an indentation style are left alone.
        tail = index + 1
        while (
            tail < end
            and not _is_blank_or_comment(lines[tail])
            and _indent_width(lines[tail]) > option_indent
        ):
            lines[tail] = ""
            tail += 1
        return "".join(lines)

    # Present but unset: append to the section, before its trailing blank lines.
    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines.insert(insert_at, f"{option} = {value}\n")
    return "".join(lines)


def _ensure_user_config():
    """Return the configuration file to use, seeding it on first run.

    The bundled file is either a virgin template on a fresh install or the
    user's own populated file on an upgrade, so a single copy handles both.
    After this runs once, the plugin directory is never written to again and
    upgrades stop destroying API keys.
    """
    user_config = gepetto.paths.config_file()
    if user_config.exists():
        return user_config

    bundled = gepetto.paths.bundled_config()
    try:
        user_config.parent.mkdir(parents=True, exist_ok=True)
        if bundled.exists():
            shutil.copyfile(bundled, user_config)
        else:
            user_config.touch()
        if os.name == "posix":
            os.chmod(user_config, 0o600)
    except OSError as e:
        print(f"Gepetto: could not create {user_config} ({e}); falling back to {bundled}.")
        return bundled

    print(f"Gepetto: configuration migrated to {user_config}")
    return user_config


def load_config():
    """
    Loads the configuration of the plugin from the INI file. Sets up the correct locale and language model.
    Also prepares an OpenAI client configured accordingly to the user specifications.
    :return:
    """
    global model, parsed_ini, config_path, _translator, language, available_locales
    parsed_ini = configparser.RawConfigParser()
    config_path = _ensure_user_config()
    parsed_ini.read(config_path, encoding="utf-8")
    # A missing or truncated file must not take the plugin down: every read
    # below goes through a fallback, and the section is guaranteed to exist.
    if not parsed_ini.has_section("Gepetto"):
        parsed_ini.add_section("Gepetto")

    # Read available locales from the locales directory
    locales_dir = str(gepetto.paths.locales_dir())
    available_locales = set()
    if os.path.exists(locales_dir):
        for item in os.listdir(locales_dir):
            item_path = os.path.join(locales_dir, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                available_locales.add(item)

    # Set up translations
    language = parsed_ini.get('Gepetto', 'LANGUAGE', fallback='')
    translate = gettext.translation('gepetto',
                                    locales_dir,
                                    fallback=True,
                                    languages=[language])
    _translator = translate.gettext

    # Select model
    requested_model = parsed_ini.get('Gepetto', 'MODEL', fallback='')
    load_available_models()
    # Attempt to load the requested model, otherwise get the first available one, or don't load Gepetto
    try:
        model = instantiate_model(requested_model)
    except Exception:
        # Deliberately broad: a third-party provider's constructor can raise
        # anything, and that must cost the user that one provider, not the
        # whole plugin.
        print(_("Attempting to load the first available model..."))
        try:
            model = get_fallback_model()
            print(f"Defaulted to {str(model)}.")
        except Exception:
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
    path = pathlib.Path(config_path or _ensure_user_config())
    value = _stringify_config_value(new_value)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        text = ""
    path.write_text(_set_option_in_text(text, section, option, value), encoding="utf-8")

    global parsed_ini
    if parsed_ini is not None:
        if not parsed_ini.has_section(section):
            parsed_ini.add_section(section)
        parsed_ini.set(section, option, value)


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
