import httpx as _httpx
from gepetto.models.openai import GPT
import openai

import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

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
                proxy=proxy,
            ) if proxy else None
        )

    def query_model(self, query, cb, stream=False, *args, **kwargs):
        """
        Compatible with callers that may pass an extra positional 'context' arg:
          - query_model(query, cb, additional_model_options)
          - query_model(query, cb, context, additional_model_options)
          - query_model(query, cb, context=?, additional_model_options=?)
        We ACCEPT extra positional args but DO NOT forward them to super(),
        because GPT.query_model(...) doesn't expect them.
        """
        pos_args = list(args)

        # 1) Determine additional_model_options from kwargs or trailing positional dict
        if "additional_model_options" in kwargs:
            opt = kwargs.get("additional_model_options") or {}
            # If caller also gave a trailing positional dict, drop it to avoid dup binding
            if pos_args and isinstance(pos_args[-1], dict):
                pos_args.pop()
        else:
            if pos_args and isinstance(pos_args[-1], dict):
                opt = pos_args.pop()  # treat last positional dict as options
            else:
                opt = {}

        # 2) Make a copy so we don't mutate caller state
        additional_model_options = dict(opt)

        # 3) Keep your JSON response_format compatibility shim
        rf = additional_model_options.get("response_format", {})
        if isinstance(rf, dict) and rf.get("type") == "json_object":
            additional_model_options["response_format"] = {
                "type": "json_schema",
                "json_schema": {"schema": {"type": "object"}}
            }

        # 4) IMPORTANT: do NOT forward any other positional args to super()
        #    GPT.query_model only expects (query, cb, additional_model_options)
        return super().query_model(
            query,
            cb,
            stream,
            additional_model_options=additional_model_options,
        )

gepetto.models.model_manager.register_model(LMStudio)
