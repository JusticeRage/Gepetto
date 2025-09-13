import gepetto.config

# Install Qt compatibility shim before any UI modules are imported.
# This keeps PySide6 paths working on IDA 9.2+, and aliases them to
# PyQt5 (Qt5) on older IDA versions without changing the rest of the code.
try:
    from gepetto import qt_compat as _qt_compat  # type: ignore
    _qt_compat.install()
except Exception:
    # Never fail the plugin just because the shim couldn't install.
    pass


def PLUGIN_ENTRY():
    gepetto.config.load_config()  # Loads configuration data from gepetto/config.ini

    # Only import the rest of the code after the translations have been loaded, because the _ function (gettext)
    # needs to have been imported in the namespace first.
    from gepetto.ida.ui import GepettoPlugin
    return GepettoPlugin()
