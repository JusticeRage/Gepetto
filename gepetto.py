import gepetto.config


def PLUGIN_ENTRY():
    gepetto.config.load_config()  # Loads configuration data from gepetto/config.ini

    # Only load the rest of the code after the translations have been loaded
    from gepetto.ida.ui import GepettoPlugin
    return GepettoPlugin()
