import functools
import threading

import httpx as _httpx
import ida_kernwin
import ollama

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

OLLAMA_MODELS = None

def create_client(**kwargs):
    host = gepetto.config.get_config("Ollama", "HOST", default="http://localhost:11434")
    return ollama.Client(host=host, **kwargs)

class Ollama(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Ollama"

    @staticmethod
    def supported_models():
        global OLLAMA_MODELS
        if OLLAMA_MODELS is None:
            try:
                # User a shorter timeout to avoid hanging IDA at startup is the server is unreachable.
                OLLAMA_MODELS = [m["model"] for m in create_client(timeout=2).list()["models"]]
            except (_httpx.ConnectError, _httpx.ConnectTimeout, ollama.ResponseError, ConnectionError):
                OLLAMA_MODELS = []
        return OLLAMA_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if it exposes any model.
        return len(Ollama.supported_models()) > 0

    def __str__(self):
        return self.model

    def __init__(self, model):
        self.model = model
        self.client = create_client()
        # Cancellation primitives
        import threading as _thr
        self._cancel_lock = _thr.Lock()
        self._cancel_ev: _thr.Event | None = None
        self._active_response = None

    def query_model_async(self, query, cb, stream=False, additional_model_options = None):
        if additional_model_options is None:
            additional_model_options = {}
        t = threading.Thread(target=self.query_model, args=[query, cb, stream, additional_model_options])
        t.start()

    def query_model(self, query, cb, stream=False, additional_model_options=None):
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

            response = self.client.chat(model=self.model,
                                        messages=conversation,
                                        stream=stream,
                                        **kwargs)
            if not stream:
                ida_kernwin.execute_sync(functools.partial(cb, response=response["message"]["content"]),
                                         ida_kernwin.MFF_WRITE)
            else:
                # Initialize/record cancel state for this request
                with self._cancel_lock:
                    import threading as _thr
                    self._cancel_ev = getattr(self, "_cancel_ev", None) or _thr.Event()
                    self._active_response = response
                for chunk in response:
                    # Cancellation check
                    if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                        try:
                            close = getattr(response, "close", None)
                            if callable(close):
                                close()
                        except Exception:
                            pass
                        with self._cancel_lock:
                            self._active_response = None
                        break
                    cb(chunk['message']['content'], finished=chunk['done'])
        except Exception as e:
            print(e)


    def cancel_current_request(self):
        """Signal cancellation to any in‑flight streaming request."""
        try:
            with self._cancel_lock:
                ev = getattr(self, "_cancel_ev", None)
                resp = getattr(self, "_active_response", None)
                if ev is not None:
                    ev.set()
                if resp is not None:
                    try:
                        close = getattr(resp, "close", None)
                        if callable(close):
                            close()
                    except Exception:
                        pass
        except Exception:
            pass

gepetto.models.model_manager.register_model(Ollama)
