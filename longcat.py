import openai
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT

LONGCAT_MODEL_NAME = "LongCat-Flash-Chat"


class LongCat(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "LongCat"

    @staticmethod
    def supported_models():
        return [LONGCAT_MODEL_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("LongCat", "API_KEY", "LONGCAT_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass

        self.model = model
        api_key = gepetto.config.get_config("LongCat", "API_KEY", "LONGCAT_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="LongCat"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("LongCat", "BASE_URL", "LONGCAT_BASE_URL")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(proxy=proxy) if proxy else None
        )


gepetto.models.model_manager.register_model(LongCat)
