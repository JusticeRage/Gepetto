import asyncio
import functools
import threading
import time

import httpx as _httpx
import ida_kernwin
import ollama

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

OLLAMA_MODELS = None
_OLLAMA_MODELS_LOCK = threading.Lock()
_OLLAMA_REFRESH_THREAD: threading.Thread | None = None
_OLLAMA_LAST_REFRESH: float = 0.0

def create_client(**kwargs):
    host = gepetto.config.get_config("Ollama", "HOST", default="http://localhost:11434")
    return ollama.Client(host=host, **kwargs)


def _trigger_menu_refresh() -> None:
    try:
        from gepetto.ida import ui as ida_ui
        ida_ui.trigger_model_select_menu_regeneration()
    except Exception:
        pass


def _normalize_host(host: str | None) -> str:
    if not host:
        host = "http://localhost:11434"
    return host.rstrip("/")


def _update_ollama_models(models: list[str], *, notify: bool = True) -> None:
    global OLLAMA_MODELS
    normalized = sorted(dict.fromkeys(models))
    with _OLLAMA_MODELS_LOCK:
        current = list(OLLAMA_MODELS) if OLLAMA_MODELS is not None else []
        if normalized == current:
            return
        OLLAMA_MODELS = normalized
    if notify:
        _trigger_menu_refresh()


def _execute_ollama_fetch(host: str | None, timeout: _httpx.Timeout) -> list[str]:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_fetch_ollama_models_async(host, timeout))
    except Exception as exc:
        resolved_host = _normalize_host(host)
        print(
            _("Failed to fetch models from {base_url}: {error}").format(
                base_url=f"{resolved_host}/api/tags",
                error=exc,
            )
        )
        return []
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def _schedule_ollama_refresh(host: str | None, timeout: _httpx.Timeout) -> None:
    global _OLLAMA_REFRESH_THREAD, _OLLAMA_LAST_REFRESH
    with _OLLAMA_MODELS_LOCK:
        if _OLLAMA_REFRESH_THREAD and _OLLAMA_REFRESH_THREAD.is_alive():
            return
        now = time.monotonic()
        if now - _OLLAMA_LAST_REFRESH < 5.0:
            return
        _OLLAMA_LAST_REFRESH = now
        _OLLAMA_REFRESH_THREAD = threading.Thread(
            target=_refresh_ollama_models_background,
            args=(host, timeout),
            name="GepettoOllamaModelRefresh",
            daemon=True,
        )
        _OLLAMA_REFRESH_THREAD.start()


def _refresh_ollama_models_background(host: str | None, timeout: _httpx.Timeout) -> None:
    global _OLLAMA_REFRESH_THREAD
    try:
        models = _execute_ollama_fetch(host, timeout)
        if models:
            _update_ollama_models(models)
    finally:
        with _OLLAMA_MODELS_LOCK:
            _OLLAMA_REFRESH_THREAD = None


async def _fetch_ollama_models_async(host: str | None, timeout: _httpx.Timeout) -> list[str]:
    resolved_host = _normalize_host(host)
    endpoint = f"{resolved_host}/api/tags"
    try:
        async with _httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(endpoint)
    except (
        _httpx.ConnectError,
        _httpx.ConnectTimeout,
        _httpx.ReadTimeout,
        _httpx.TimeoutException,
    ):
        return []

    if response.status_code != 200:
        print(
            _("Failed to fetch models from {base_url}: {status_code}").format(
                base_url=endpoint,
                status_code=response.status_code,
            )
        )
        return []

    payload = response.json() or {}
    models = [
        model.get("model")
        for model in payload.get("models", [])
        if isinstance(model, dict) and model.get("model")
    ]
    models.sort()
    return models

class Ollama(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Ollama"

    @staticmethod
    def supported_models():
        global OLLAMA_MODELS
        with _OLLAMA_MODELS_LOCK:
            if OLLAMA_MODELS is None:
                OLLAMA_MODELS = []
            models = list(OLLAMA_MODELS)

        host = gepetto.config.get_config("Ollama", "HOST", default="http://localhost:11434")
        timeout = _httpx.Timeout(2.0, connect=2.0)
        _schedule_ollama_refresh(host, timeout)
        return models

    @staticmethod
    def is_configured_properly() -> bool:
        return True

    @staticmethod
    def refresh_models_sync() -> list[str]:
        host = gepetto.config.get_config("Ollama", "HOST", default="http://localhost:11434")
        timeout = _httpx.Timeout(2.0, connect=2.0)
        models = _execute_ollama_fetch(host, timeout)
        if models:
            _update_ollama_models(models)
        with _OLLAMA_MODELS_LOCK:
            current = list(OLLAMA_MODELS) if OLLAMA_MODELS is not None else []
        return current

    def __str__(self):
        return self.model

    def __init__(self, model):
        self.model = model
        self.client = create_client()

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
                for chunk in response:
                    cb(chunk['message'], chunk.done_reason)
        except Exception as e:
            print(e)


gepetto.models.model_manager.register_model(Ollama)
