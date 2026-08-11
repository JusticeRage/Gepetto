"""Filesystem locations used by Gepetto.

Split out of ``config.py`` so that plugin-relative assets (locales, the bundled
configuration template) and user-owned data (the live configuration, drop-in
providers) resolve independently, and so tests have a single seam to redirect.
"""

import os
import pathlib

# Directory the plugin's code lives in. Ships with the plugin, replaced wholesale
# on upgrade: never write here.
PLUGIN_DIR = pathlib.Path(__file__).resolve().parent


def bundled_config() -> pathlib.Path:
    """The configuration template shipped with the plugin."""
    return PLUGIN_DIR / "config.ini"


def locales_dir() -> pathlib.Path:
    """Translations. A shipped code asset, not user data."""
    return PLUGIN_DIR / "locales"


def _ida_user_dir():
    """$IDAUSR according to IDA itself, or None outside IDA.

    ``ida_diskio`` is imported lazily on purpose: under idalib the native
    modules only exist after ``import idapro``, and ``gepetto.py`` defers every
    IDA import until after ``load_config()`` has run.
    """
    try:
        import ida_diskio
    except Exception:
        return None
    try:
        resolved = ida_diskio.get_user_idadir()
    except Exception:
        return None
    return pathlib.Path(resolved) if resolved else None


def _env_user_dir():
    """$IDAUSR from the environment, or None.

    IDA accepts a list of directories separated by ';' on Windows and ':'
    elsewhere. Only the first is used, matching get_user_idadir().
    """
    raw = os.environ.get("IDAUSR")
    if not raw:
        return None
    separator = ";" if os.name == "nt" else ":"
    first = raw.split(separator)[0].strip()
    return pathlib.Path(first).expanduser() if first else None


def user_dir() -> pathlib.Path:
    """Directory holding the live configuration and any drop-in providers."""
    override = os.environ.get("GEPETTO_CONFIG_DIR")
    if override:
        return pathlib.Path(override).expanduser()
    base = _ida_user_dir() or _env_user_dir() or pathlib.Path.home() / ".idapro"
    return base / "cfg" / "gepetto"


def config_file() -> pathlib.Path:
    return user_dir() / "config.ini"


def providers_dir() -> pathlib.Path:
    return user_dir() / "providers"
