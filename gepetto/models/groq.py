import groq
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT


LLAMA_31_MODEL_NAME = "llama-3.1-70b-versatile"
LLAMA_32_MODEL_NAME = "llama-3.2-90b-text-preview"
MIXTRAL_MODEL_NAME = "mixtral-8x7b-32768"

class Groq(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "Groq"

    @staticmethod
    def supported_models():
        return [LLAMA_31_MODEL_NAME, LLAMA_32_MODEL_NAME, MIXTRAL_MODEL_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("Groq", "API_KEY", "GROQ_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need any to use Groq.

        self.model = model
        api_key = gepetto.config.get_config("Groq", "API_KEY", "GROQ_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="Groq"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("Groq", "BASE_URL", "GROQ_BASE_URL")

        self.client = groq.Groq(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

gepetto.models.model_manager.register_model(Groq)
