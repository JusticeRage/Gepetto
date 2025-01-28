import openai
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT

DEEPSEEK_CHAT_NAME = "deepseek-chat"

class DeepSeek(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "DeepSeek"

    @staticmethod
    def supported_models():
        return [DEEPSEEK_CHAT_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("DeepSeek", "API_KEY", "DEEPSEEK_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need any to use DeepSeek.

        self.model = model
        api_key = gepetto.config.get_config("DeepSeek", "API_KEY", "DEEPSEEK_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="DeepSeek"))
                             
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("DeepSeek", "BASE_URL", "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

gepetto.models.model_manager.register_model(DeepSeek)
