import configparser
import gettext
import os

from gepetto.models.base import get_model

translate = None
model = None
parsed_ini = None


def load_config():
    """
    Loads the configuration of the plugin from the INI file. Sets up the correct locale and language model.
    Also prepares an OpenAI client configured accordingly to the user specifications.
    :return:
    """
    global translate, model, parsed_ini
    parsed_ini = configparser.RawConfigParser()
    parsed_ini.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini"))

    # Set up translations
    language = parsed_ini.get('Gepetto', 'LANGUAGE')
    translate = gettext.translation('gepetto',
                                    os.path.join(os.path.abspath(os.path.dirname(__file__)), "locales"),
                                    fallback=True,
                                    languages=[language])

    # Select model
    requested_model = parsed_ini.get('Gepetto', 'MODEL')
    model = get_model(requested_model)


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
    config.read(path)
    config.set(section, option, new_value)
    with open(path, "w") as f:
        config.write(f)
