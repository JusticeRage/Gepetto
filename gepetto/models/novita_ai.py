import openai
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT


NOVITA_MODELS = [
  "deepseek/deepseek-r1",
  "deepseek/deepseek_v3",
  "meta-llama/llama-3.3-70b-instruct",
  "meta-llama/llama-3.1-70b-instruct",
  "meta-llama/llama-3.1-405b-instruct",
]

class NovitaAI(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "Novita AI"

    @staticmethod
    def supported_models():
        return NOVITA_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("NovitaAI", "API_KEY", "NOVITAAI_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need it.

        self.model = model
        api_key = gepetto.config.get_config("NovitaAI", "API_KEY", "NOVITAAI_API_KEY")
        if not api_key:
            print(_("Please edit the configuration file to insert your {api_provider} API key!")
                  .format(api_provider="Novita AI"))
            raise ValueError("No valid Novita AI API key found")

        proxy = gepetto.config.get_config("Gepetto", "PROXY")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url="https://api.novita.ai/v3/openai",
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

gepetto.models.model_manager.register_model(NovitaAI)
