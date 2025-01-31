import functools
import threading

import httpx as _httpx
import ida_kernwin
import ollama

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

OLLAMA_MODELS = None

def create_client():
    host = gepetto.config.get_config("Ollama", "HOST", default="http://localhost:11434")
    return ollama.Client(host=host)

class Ollama(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Ollama"

    @staticmethod
    def supported_models():
        global OLLAMA_MODELS
        if OLLAMA_MODELS is None:
            try:
                OLLAMA_MODELS = [m["name"] for m in create_client().list()["models"]]
            except (_httpx.ConnectError, ollama.ResponseError):
                OLLAMA_MODELS = []
        return OLLAMA_MODELS

    def __str__(self):
        return self.model

    def __init__(self, model):
        self.model = model
        self.client = create_client()

    def query_model_async(self, query, cb, additional_model_options = None):
        if additional_model_options is None:
            additional_model_options = {}
        t = threading.Thread(target=self.query_model, args=[query, cb, additional_model_options])
        t.start()

    def query_model(self, query, cb, additional_model_options=None):
        # Convert the OpenAI json parameter for Ollama
        kwargs = {}
        if "response_format" in additional_model_options and additional_model_options["response_format"]["type"] == "json_object":
            kwargs["format"] = "json"

        try:
            if type(query) is str:
                conversation = [
                    {"role": "user", "content": query}
                ]
            else:
                conversation = query

            stream = self.client.chat(model=self.model,
                                      messages=conversation,
                                      stream=False,
                                      **kwargs)
            ida_kernwin.execute_sync(functools.partial(cb, response=stream["message"]["content"]),
                                     ida_kernwin.MFF_WRITE)
        except Exception as e:
            print(e)


gepetto.models.model_manager.register_model(Ollama)
