import configparser
import gettext
import os

import openai

from gepetto.models.base import get_model

translate = None
model = None


def load_config():
    global translate, model
    config = configparser.RawConfigParser()
    config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini"))

    # Set up translations
    language = config.get('Gepetto', 'LANGUAGE')
    translate = gettext.translation('gepetto',
                                    os.path.join(os.path.abspath(os.path.dirname(__file__)), "gepetto/locales"),
                                    fallback=True,
                                    languages=[language])

    # Select model
    requested_model = config.get('Gepetto', 'MODEL')
    model = get_model(requested_model)

    if not config.get('OpenAI', 'API_KEY'):
        openai.api_key = os.getenv("OPENAI_API_KEY")
