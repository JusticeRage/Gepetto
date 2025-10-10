import asyncio
import threading
import time

import httpx as _httpx
from gepetto.models.openai import GPT
import openai

import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

LMSTUDIO_MODELS = None
_LMSTUDIO_MODELS_LOCK = threading.Lock()
_LMSTUDIO_REFRESH_THREAD: threading.Thread | None = None
_LMSTUDIO_LAST_REFRESH: float = 0.0


def _trigger_menu_refresh() -> None:
    try:
        from gepetto.ida import ui as ida_ui
        ida_ui.trigger_model_select_menu_regeneration()
    except Exception:
        pass


def _normalize_base_url(base_url: str | None) -> str:
    if not base_url:
        base_url = "http://127.0.0.1:1234/v1/"
    if not base_url.endswith("/"):
        base_url = base_url + "/"
    return base_url


def _update_lmstudio_models(models: list[str], *, notify: bool = True) -> None:
    global LMSTUDIO_MODELS
    normalized = sorted(dict.fromkeys(models))
    with _LMSTUDIO_MODELS_LOCK:
        current = list(LMSTUDIO_MODELS) if LMSTUDIO_MODELS is not None else []
        if normalized == current:
            return
        LMSTUDIO_MODELS = normalized
    if notify:
        _trigger_menu_refresh()


def _execute_lmstudio_fetch(
    base_url: str | None,
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> list[str]:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(
            _fetch_lmstudio_models_async(base_url, proxy, timeout)
        )
    except Exception as exc:
        resolved_base = _normalize_base_url(base_url)
        print(
            _("Failed to fetch models from {base_url}: {error}").format(
                base_url=f"{resolved_base}models",
                error=exc,
            )
        )
        return []
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def _schedule_lmstudio_refresh(
    base_url: str | None,
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> None:
    global _LMSTUDIO_REFRESH_THREAD, _LMSTUDIO_LAST_REFRESH
    with _LMSTUDIO_MODELS_LOCK:
        if _LMSTUDIO_REFRESH_THREAD and _LMSTUDIO_REFRESH_THREAD.is_alive():
            return
        now = time.monotonic()
        if now - _LMSTUDIO_LAST_REFRESH < 5.0:
            return
        _LMSTUDIO_LAST_REFRESH = now
        _LMSTUDIO_REFRESH_THREAD = threading.Thread(
            target=_refresh_lmstudio_models_background,
            args=(base_url, proxy, timeout),
            name="GepettoLMStudioModelRefresh",
            daemon=True,
        )
        _LMSTUDIO_REFRESH_THREAD.start()


def _refresh_lmstudio_models_background(
    base_url: str | None,
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> None:
    global _LMSTUDIO_REFRESH_THREAD
    try:
        models = _execute_lmstudio_fetch(base_url, proxy, timeout)
        if models:
            _update_lmstudio_models(models)
    finally:
        with _LMSTUDIO_MODELS_LOCK:
            _LMSTUDIO_REFRESH_THREAD = None


async def _fetch_lmstudio_models_async(
    base_url: str | None,
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> list[str]:
    resolved_base = _normalize_base_url(base_url)
    endpoint = f"{resolved_base}models"
    transport = None
    if proxy:
        try:
            transport = _httpx.AsyncHTTPTransport(proxy=proxy)
        except Exception as transport_exc:
            print(
                _("Failed to configure proxy for LM Studio models: {error}").format(
                    error=transport_exc
                )
            )
    try:
        async with _httpx.AsyncClient(timeout=timeout, transport=transport) as client:
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
        model.get("id")
        for model in payload.get("data", [])
        if isinstance(model, dict) and model.get("id")
    ]
    models.sort()
    return models

class LMStudio(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "LM Studio"

    @staticmethod
    def supported_models() -> list:
        global LMSTUDIO_MODELS
        with _LMSTUDIO_MODELS_LOCK:
            if LMSTUDIO_MODELS is None:
                LMSTUDIO_MODELS = []
            models = list(LMSTUDIO_MODELS)

        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", default="http://127.0.0.1:1234/v1/")
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        timeout = _httpx.Timeout(2.0, connect=2.0)
        _schedule_lmstudio_refresh(base_url, proxy, timeout)
        return models

    @staticmethod
    def is_configured_properly() -> bool:
        return True

    @staticmethod
    def refresh_models_sync() -> list[str]:
        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", default="http://127.0.0.1:1234/v1/")
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        timeout = _httpx.Timeout(2.0, connect=2.0)
        models = _execute_lmstudio_fetch(base_url, proxy, timeout)
        if models:
            _update_lmstudio_models(models)
        with _LMSTUDIO_MODELS_LOCK:
            current = list(LMSTUDIO_MODELS) if LMSTUDIO_MODELS is not None else []
        return current

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            # Ensure streaming state flags exist even when OpenAI init fails
            self._streaming_restriction_active = False
            self._fallback_notice_sent = False

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
