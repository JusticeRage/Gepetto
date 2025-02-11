import httpx as _httpx
from gepetto.models.openai import GPT
import openai

import gepetto.models.model_manager
import gepetto.config

LMSTUDIO_MODELS = None

class LMStudio(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "LM Studio"

    @staticmethod
    def supported_models() -> list:
        global LMSTUDIO_MODELS

        if LMSTUDIO_MODELS is not None:
            return LMSTUDIO_MODELS

        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", default="http://127.0.0.1:1234/v1/")
        try:
            response = _httpx.get(f"{base_url}models", timeout=2)
            if response.status_code == 200:
                data = response.json().get("data", [])
                LMSTUDIO_MODELS = [model["id"] for model in data]
            else:
                print(_("Failed to fetch models from {base_url}: {status_code}").format(
                    base_url=base_url, status_code=response.status_code
                ))
                LMSTUDIO_MODELS = []
        except (_httpx.ConnectError, _httpx.ConnectTimeout):
            LMSTUDIO_MODELS = []

        return LMSTUDIO_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        return len(LMStudio.supported_models()) > 0

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass

        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", default="http://127.0.0.1:1234/v1/")
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
        if additional_model_options is not None and additional_model_options.get("response_format", {}).get("type") == "json_object":
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

gepetto.models.model_manager.register_model(LMStudio)
