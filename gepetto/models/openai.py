import asyncio
import functools
import re
import threading
import time

import httpx as _httpx
import ida_kernwin
import openai
from types import SimpleNamespace

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

GPT_52_MODEL_NAME = "gpt-5.2"
GPT_51_MODEL_NAME = "gpt-5.1"
GPT_5_MODEL_NAME = "gpt-5"
GPT_5_MINI_MODEL_NAME = "gpt-5-mini"
GPT_5_NANO_MODEL_NAME = "gpt-5-nano"
GPT4_MODEL_NAME = "gpt-4-turbo"
GPT4o_MODEL_NAME = "gpt-4o"
GPTo4_MINI_MODEL_NAME = "o4-mini"
GPT41_MODEL_NAME = "gpt-4.1"
GPTo3_MODEL_NAME = "o3"
GPTo3_PRO_MODEL_NAME = "o3-pro"

_DEFAULT_OPENAI_MODELS = [
    GPT_52_MODEL_NAME,
    GPT_51_MODEL_NAME,
    GPT_5_MODEL_NAME,
    GPT_5_MINI_MODEL_NAME,
    GPT_5_NANO_MODEL_NAME,
    GPT4_MODEL_NAME,
    GPT4o_MODEL_NAME,
    GPTo4_MINI_MODEL_NAME,
    GPT41_MODEL_NAME,
    GPTo3_MODEL_NAME,
    GPTo3_PRO_MODEL_NAME,
]

_OPENAI_MODELS: list[str] | None = None
_OPENAI_MODELS_LOCK = threading.Lock()
_OPENAI_REFRESH_THREAD: threading.Thread | None = None
_OPENAI_LAST_REFRESH: float = 0.0

OPENAI_RESTRICTED_MODELS = {
    GPT_52_MODEL_NAME,
    GPT_51_MODEL_NAME,
    GPT_5_MODEL_NAME,
    GPT_5_MINI_MODEL_NAME,
    GPTo3_MODEL_NAME,
    GPTo3_PRO_MODEL_NAME,
}

_STREAMING_RESTRICTION_PATTERNS = (
    "organization is not verified",
    "must be verified",
    "'param': 'stream'",
    '"param": "stream"',
    "verify your organization",
    "unsupported for this organization",
    "streaming is not currently supported",
)


def _is_supported_openai_model(model_id: str) -> bool:
    """Return True if model_id should appear in the chat model menu."""
    if not model_id:
        return False
    lowered = model_id.lower()
    if re.search(
        r"-\d{4}(-\d{2}-\d{2})?$|tts|omni|realtime|image|audio|transcribe", 
        lowered
    ):
        return False
    if lowered.startswith("gpt-"):
        return True
    # Accept optimized o* chat models (o3, o4-mini, etc.)
    return lowered.startswith("o")


def _sort_openai_models(models: list[str]) -> list[str]:
    deduped = list(dict.fromkeys(models))
    default_models_set = set(_DEFAULT_OPENAI_MODELS)
    other_models = [m for m in deduped if m not in default_models_set]
    other_models.sort(key=str, reverse=True)
    return _DEFAULT_OPENAI_MODELS + other_models


def _trigger_menu_refresh() -> None:
    try:
        from gepetto.ida import ui as ida_ui
        ida_ui.trigger_model_select_menu_regeneration()
    except Exception:
        pass


def _update_openai_models(models: list[str], *, notify: bool = True) -> None:
    global _OPENAI_MODELS
    normalized = _sort_openai_models(models)
    with _OPENAI_MODELS_LOCK:
        current = list(_OPENAI_MODELS) if _OPENAI_MODELS is not None else []
        if normalized == current:
            return
        _OPENAI_MODELS = normalized
    if notify:
        _trigger_menu_refresh()


def _execute_openai_fetch(
    endpoint: str,
    headers: dict[str, str],
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> list[str]:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(
            _fetch_openai_models_async(endpoint, headers, proxy, timeout)
        )
    except Exception as exc:
        print(_("Failed to fetch OpenAI models: {error}").format(error=exc))
        return []
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def _schedule_openai_refresh(
    endpoint: str,
    headers: dict[str, str],
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> None:
    global _OPENAI_REFRESH_THREAD, _OPENAI_LAST_REFRESH
    with _OPENAI_MODELS_LOCK:
        if _OPENAI_REFRESH_THREAD and _OPENAI_REFRESH_THREAD.is_alive():
            return
        now = time.monotonic()
        if now - _OPENAI_LAST_REFRESH < 5.0:
            return
        _OPENAI_LAST_REFRESH = now
        _OPENAI_REFRESH_THREAD = threading.Thread(
            target=_refresh_openai_models_background,
            args=(endpoint, headers, proxy, timeout),
            name="GepettoOpenAIModelRefresh",
            daemon=True,
        )
        _OPENAI_REFRESH_THREAD.start()


def _refresh_openai_models_background(
    endpoint: str,
    headers: dict[str, str],
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> None:
    global _OPENAI_REFRESH_THREAD
    try:
        models = _execute_openai_fetch(endpoint, headers, proxy, timeout)
        if models:
            _update_openai_models(models)
    finally:
        with _OPENAI_MODELS_LOCK:
            _OPENAI_REFRESH_THREAD = None


async def _fetch_openai_models_async(
    endpoint: str,
    headers: dict[str, str],
    proxy: str | None,
    timeout: _httpx.Timeout,
) -> list[str]:
    transport = None
    if proxy:
        try:
            transport = _httpx.AsyncHTTPTransport(proxy=proxy)
        except Exception as transport_exc:
            print(
                _("Failed to configure proxy for OpenAI models: {error}").format(
                    error=transport_exc
                )
            )
    try:
        async with _httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            response = await client.get(endpoint, headers=headers)
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

    data = response.json() or {}
    models = [
        model_id
        for model_id in (
            (model or {}).get("id")
            for model in data.get("data", [])
        )
        if _is_supported_openai_model(model_id)
    ]
    return _sort_openai_models(models or list(_DEFAULT_OPENAI_MODELS))


def _notify_stream_error(callback, message: str) -> None:
    if callback is None:
        return

    payload = SimpleNamespace(error=message)
    try:
        callback(payload, "error")
    except TypeError:
        callback(payload)


def _notify_non_stream_error(callback, message: str) -> None:
    if callback is None:
        return

    payload = SimpleNamespace(error=message)

    def _invoke_callback():
        try:
            callback(payload)
        except TypeError:
            callback(payload, "error")

    ida_kernwin.execute_sync(_invoke_callback, ida_kernwin.MFF_WRITE)


class GPT(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "OpenAI"

    @staticmethod
    def supported_models():
        global _OPENAI_MODELS
        fallback = _sort_openai_models(list(_DEFAULT_OPENAI_MODELS))
        with _OPENAI_MODELS_LOCK:
            if _OPENAI_MODELS is None:
                _OPENAI_MODELS = list(fallback)
            current = list(_OPENAI_MODELS)

        api_key = gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY")
        if not api_key:
            return current

        base_url = gepetto.config.get_config("OpenAI", "BASE_URL", "OPENAI_BASE_URL")
        if not base_url:
            base_url = "https://api.openai.com/v1"
        base_url = base_url.rstrip("/")
        endpoint = f"{base_url}/models"

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = _httpx.Timeout(2.0, connect=2.0)
        _schedule_openai_refresh(endpoint, headers, proxy, timeout)
        return current

    @staticmethod
    def refresh_models_sync() -> list[str]:
        api_key = gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY")
        if not api_key:
            return GPT.supported_models()

        base_url = gepetto.config.get_config("OpenAI", "BASE_URL", "OPENAI_BASE_URL")
        if not base_url:
            base_url = "https://api.openai.com/v1"
        base_url = base_url.rstrip("/")
        endpoint = f"{base_url}/models"

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = _httpx.Timeout(2.0, connect=2.0)
        models = _execute_openai_fetch(endpoint, headers, proxy, timeout)
        if models:
            _update_openai_models(models)
        with _OPENAI_MODELS_LOCK:
            current = list(_OPENAI_MODELS) if _OPENAI_MODELS is not None else list(_DEFAULT_OPENAI_MODELS)
        return current

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY"))

    def __init__(self, model):
        self.model = model
        # Get API key
        api_key = gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="OpenAI"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("OpenAI", "BASE_URL", "OPENAI_BASE_URL")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxy=proxy,
            ) if proxy else None
        )
        self._streaming_restriction_active = False
        self._fallback_notice_sent = False

    def __str__(self):
        return self.model

    def _is_restricted_model(self) -> bool:
        return self.model in OPENAI_RESTRICTED_MODELS

    @staticmethod
    def _matches_streaming_restriction(message: str) -> bool:
        if not message:
            return False
        lowered = message.lower()
        return any(pattern in lowered for pattern in _STREAMING_RESTRICTION_PATTERNS)

    def _emit_streaming_notice(self, error_message: str | None = None) -> None:
        if self._fallback_notice_sent:
            return
        if error_message:
            notice = _(
                "Streaming rejected for {model}: {error}\nRetrying without streaming."
            ).format(model=self.model, error=error_message)
        else:
            notice = _(
                "Streaming disabled for {model} after a previous API rejection; retrying without streaming."
            ).format(model=self.model)
        try:
            print(notice)
        except Exception:
            pass
        self._fallback_notice_sent = True

    def supports_streaming(self) -> bool:
        if self._streaming_restriction_active and self._is_restricted_model():
            return False
        return True

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        """
        Function which sends a query to a GPT-API-compatible model and calls a callback when the response is available.
        Blocks until the response is received
        :param query: The request to send to the model. It can be a single string, or a sequence of messages in a
        dictionary for a whole conversation.
        :param cb: The function to which the response will be passed to.
        :param additional_model_options: Additional parameters used when creating the model object. Typically, for
        OpenAI, response_format={"type": "json_object"}.
        """
        if additional_model_options is None:
            additional_model_options = {}
        
        # Disable streaming for models that don't support it
        if stream and not self.supports_streaming():
            stream = False
            self._emit_streaming_notice()
        
        try:
            if type(query) is str:
                conversation = [
                    {"role": "user", "content": query}
                ]
            else:
                conversation = query

            response = self.client.chat.completions.create(
                model=self.model,
                messages=conversation,
                stream=stream,
                **additional_model_options
            )
            if not stream:
                # Return the full message object so that callers can access
                # additional data such as tool calls when using the OpenAI
                # function calling API.
                message = response.choices[0].message
                ida_kernwin.execute_sync(
                    functools.partial(cb, response=message),
                    ida_kernwin.MFF_WRITE,
                )
            else:
                for chunk in response:
                    delta = chunk.choices[0].delta
                    finished = chunk.choices[0].finish_reason
                    cb(delta, finished)
        except openai.BadRequestError as e:
            error_message = str(e)
            if stream and self._is_restricted_model() and self._matches_streaming_restriction(error_message):
                self._streaming_restriction_active = True
                self._emit_streaming_notice(error_message)
                _notify_stream_error(cb, _("Streaming rejected by API; retrying without streaming."))
                return
            # Context length exceeded. Determine the max number of tokens we can ask for and retry.
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', error_message)
            if m:
                error_message = _(
                    "Unfortunately, this function is too big to be analyzed with the model's current API limits."
                )
            else:
                error_message = _(
                    "General exception encountered while running the query: {error}"
                ).format(error=error_message)
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)
        except openai.OpenAIError as e:
            error_message = _("{model} could not complete the request: {error}").format(
                model=self.model, error=str(e)
            )
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)
        except Exception as e:
            error_message = _("General exception encountered while running the query: {error}").format(error=str(e))
            print(error_message)
            if stream:
                _notify_stream_error(cb, error_message)
            else:
                _notify_non_stream_error(cb, error_message)

    # -----------------------------------------------------------------------------

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        """
        Function which sends a query to {model} and calls a callback when the response is available.
        :param query: The request to send to {model}
        :param cb: Tu function to which the response will be passed to.
        :param additional_model_options: Additional parameters used when creating the model object. Typically, for
        OpenAI, response_format={"type": "json_object"}.
        """
        t = threading.Thread(target=self.query_model, args=[query, cb, stream, additional_model_options])
        t.start()

gepetto.models.model_manager.register_model(GPT)
