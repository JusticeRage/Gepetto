import groq
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT


GROQ_MODEL_NAME = "llama-3.1-70b-versatile"

class Groq(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "Groq"

    @staticmethod
    def supported_models():
        return [GROQ_MODEL_NAME]

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need any to use Groq.

        self.model = model
        api_key = gepetto.config.get_config("Groq", "API_KEY", "GROQ_API_KEY")
        if not api_key:
            print(_("Please edit the configuration file to insert your {api_provider} API key!")
                  .format(api_provider="Groq"))
            raise ValueError("No valid Groq API key found")

        proxy = gepetto.config.get_config("Groq", "GROQ_PROXY")
        base_url = gepetto.config.get_config("Groq", "BASE_URL", "GROQ_BASE_URL")

        self.client = groq.Groq(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

gepetto.models.model_manager.register_model(Groq)
