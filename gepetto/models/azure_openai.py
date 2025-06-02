import httpx as _httpx

import openai
from azure.identity import InteractiveBrowserCredential, get_bearer_token_provider
from gepetto.models.openai import GPT
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

AZURE_OPENAI_MODELS = [
    "gpt-35-turbo",
    "gpt-35-turbo-1106",
    "gpt-35-turbo-16k",
    "gpt-4-turbo",
    "gpt-4-turbo-2024-0409-gs"
]


class AzureOpenAI(GPT):
    API_VERSION = "2024-05-01-preview"

    @staticmethod
    def get_menu_name() -> str:
        return "Azure OpenAI"

    @staticmethod
    def supported_models():
        return AZURE_OPENAI_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the resource URL is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("AzureOpenAI", "BASE_URL", "AZURE_OPENAI_URL"))

    def __init__(self, model):
        self.model = model
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("AzureOpenAI", "BASE_URL", "AZURE_OPENAI_URL")
        api_key = gepetto.config.get_config(
            "AzureOpenAI", "API_KEY", "AZURE_OPENAI_API_KEY")

        if api_key:
            self.client = openai.AzureOpenAI(
                azure_endpoint=base_url,
                api_key=api_key,
                api_version=self.API_VERSION,
                http_client=_httpx.Client(
                    proxy=proxy,
                ) if proxy else None
            )
        else:
            # Entra ID authentication
            token_provider = get_bearer_token_provider(
                InteractiveBrowserCredential(),
                "https://cognitiveservices.azure.com/.default"
            )
            self.client = openai.AzureOpenAI(
                azure_endpoint=base_url,
                azure_ad_token_provider=token_provider,
                api_version=self.API_VERSION,
                http_client=_httpx.Client(
                    proxy=proxy,
                ) if proxy else None
            )


gepetto.models.model_manager.register_model(AzureOpenAI)
