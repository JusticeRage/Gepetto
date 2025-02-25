import openai
import httpx as _httpx
import json
import os

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT

# Default models to expose through OpenRouter
# You can override these in config.ini
DEFAULT_OPENROUTER_MODELS = [
    "anthropic/claude-3-5-sonnet",
    "anthropic/claude-3.7-sonnet",
    "google/gemini-2.0-flash-thinking-exp:free",
    "deepseek/deepseek-r1",
]

class OpenRouter(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "OpenRouter"

    @staticmethod
    def supported_models():
        # Check if custom models are defined in config
        config_models = gepetto.config.get_config("OpenRouter", "MODELS")
        if config_models:
            try:
                return json.loads(config_models)
            except json.JSONDecodeError:
                # If it's not valid JSON, treat it as comma-separated list
                return [model.strip() for model in config_models.split(",")]
        return DEFAULT_OPENROUTER_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided
        return bool(gepetto.config.get_config("OpenRouter", "API_KEY", "OPENROUTER_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need it

        self.model = model
        api_key = gepetto.config.get_config("OpenRouter", "API_KEY", "OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="OpenRouter"))
        
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("OpenRouter", "BASE_URL", "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

gepetto.models.model_manager.register_model(OpenRouter)
