import openai
import json
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT

DEFAULT_ALIYUN_MODELS = [
    "qwen-max",
    "qwen-plus",
    "qwq-plus",
    "qwq-32b",
    "deepseek-v3",
    "deepseek-r1",
    "qwen-coder-plus",
    "qwen-omni-turbo",
]


class Aliyun(GPT):

    @staticmethod
    def get_menu_name() -> str:
        return "Aliyun"

    @staticmethod
    def supported_models():
        # Check if custom models are defined in config
        # If not, use the default models
        config_models = gepetto.config.get_config("Aliyun", "MODELS")
        if config_models:
            try:
                return json.loads(config_models)
            except json.JSONDecodeError:
                # If it's not valid JSON, treat it as comma-separated list
                return [model.strip() for model in config_models.split(",")]
        return DEFAULT_ALIYUN_MODELS

    @staticmethod
    def is_configured_properly() -> bool:

        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(
            gepetto.config.get_config("Aliyun", "API_KEY",
                                      "ALIYUN_API_KEY"))

    def __init__(self, model):
        try:

            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need any to use DeepSeek.

        self.model = model
        api_key = gepetto.config.get_config("Aliyun", "API_KEY",
                                            "ALIYUN_API_KEY")
        if not api_key:
            raise ValueError(
                _("Please edit the configuration file to insert your {api_provider} API key!"
                  ).format(api_provider="Aliyun"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("Aliyun", "BASE_URL",
                                             "ALIYUN_BASE_URL",
                                             "https://dashscope.aliyuncs.com/compatible-mode/v1")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(proxy=proxy) if proxy else None)


gepetto.models.model_manager.register_model(Aliyun)
