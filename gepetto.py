import gepetto.config
from gepetto.ida.utils.debug import enable_debug_mode_from_config

def PLUGIN_ENTRY():
    gepetto.config.load_config()  # Loads configuration data from gepetto/config.ini
    # Enable debug logging/excepthook when configured (env or config)
    enable_debug_mode_from_config()

    # Only import the rest of the code after the translations have been loaded, because the _ function (gettext)
    # needs to have been imported in the namespace first.
    from gepetto.ida.ui import GepettoPlugin
    return GepettoPlugin()
