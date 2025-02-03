import functools
import re
import threading

import httpx as _httpx
from gepetto.models.openai import GPT
import ida_kernwin
import openai
from pyexpat.errors import messages

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

class LMStudio(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "LM Studio"

    @staticmethod
    def supported_models() -> list:
        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", "http://127.0.0.1:1234/v1/")
        response = _httpx.get(f"{base_url}models")
        if response.status_code == 200:
            models = response.json().get("data", [])
            return [model["id"] for model in models]
        else:
            print(_("Failed to fetch models from {base_url}: {status_code}").format(base_url=base_url, status_code=response.status_code))
            return []

    @staticmethod
    def is_configured_properly() -> bool:
        return True

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass
        
        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", "http://127.0.0.1:1234/v1/")
        proxy = gepetto.config.get_config("Gepetto", "PROXY")

        self.model = model
        self.client = openai.OpenAI(
            api_key="NO_API_KEY",
            base_url=base_url,
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

    def query_model(self, query, cb, additional_model_options=None):
        if additional_model_options is not None:
            additional_model_options.update({
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "schema": {
                            "type": "object"
                        }
                    }
                }
            })
        else:
            additional_model_options = {}

        super().query_model(query, cb, additional_model_options)

    # -----------------------------------------------------------------------------

    def query_model_async(self, query, cb, additional_model_options=None):
        super().query_model_async(query, cb, additional_model_options)

gepetto.models.model_manager.register_model(LMStudio)
