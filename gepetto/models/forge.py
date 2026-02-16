import openai
import json
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT

_ = gepetto.config._

# Default models to expose through Forge
# You can override these in config.ini
DEFAULT_FORGE_MODELS = [
    "OpenAI/gpt-4o-mini",
    "OpenAI/gpt-4o",
    "anthropic/claude-3-5-sonnet",
    "deepseek/deepseek-chat",
]

class Forge(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "Forge"

    @staticmethod
    def supported_models():
        # Check if custom models are defined in config
        config_models = gepetto.config.get_config("Forge", "MODELS")
        if config_models:
            try:
                return json.loads(config_models)
            except json.JSONDecodeError:
                # If it's not valid JSON, treat it as comma-separated list
                return [model.strip() for model in config_models.split(",")]
        return DEFAULT_FORGE_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided
        return bool(gepetto.config.get_config("Forge", "API_KEY", "FORGE_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need it

        self.model = model
        api_key = gepetto.config.get_config("Forge", "API_KEY", "FORGE_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="Forge"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("Forge", "BASE_URL", "FORGE_API_BASE", "https://api.forge.tensorblock.co/v1")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxy=proxy,
            ) if proxy else None
        )

gepetto.models.model_manager.register_model(Forge)
