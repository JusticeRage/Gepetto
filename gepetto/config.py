import configparser
import gettext
import os

import openai

from gepetto.models.base import get_model

translate = None
model = None


def load_config():
    """
    Loads the configuration of the plugin from the INI file. Sets up the correct locale and language model.
    :return:
    """
    global translate, model
    config = configparser.RawConfigParser()
    config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini"))

    # Set up translations
    language = config.get('Gepetto', 'LANGUAGE')
    translate = gettext.translation('gepetto',
                                    os.path.join(os.path.abspath(os.path.dirname(__file__)), "locales"),
                                    fallback=True,
                                    languages=[language])

    # Get API keys
    if not config.get('OpenAI', 'API_KEY'):
        openai.api_key = os.getenv("OPENAI_API_KEY")
    else:
        openai.api_key = config.get('OpenAI', 'API_KEY')
        print(f"Key set to {openai.api_key}")

    # Select model
    requested_model = config.get('Gepetto', 'MODEL')
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
