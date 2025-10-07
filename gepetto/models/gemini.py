from __future__ import annotations

import functools
import json
import threading
from collections.abc import Iterable
from types import SimpleNamespace
from typing import Any

import ida_kernwin
from google import genai
from google.genai import types

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

GEMINI_2_0_FLASH_MODEL_NAME = "gemini-2.0-flash"
GEMINI_2_5_PRO_MODEL_NAME = "gemini-2.5-pro"
GEMINI_2_5_FLASH_MODEL_NAME = "gemini-2.5-flash"
GEMINI_FLASH_LATEST_MODEL_NAME = "gemini-flash-latest"
GEMINI_FLASH_LITE_LATEST_MODEL_NAME = "gemini-flash-lite-latest"

_DEFAULT_SAFETY_SETTINGS: tuple[types.SafetySetting, ...] = (
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE,
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold=types.HarmBlockThreshold.BLOCK_NONE,
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE,
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE,
    ),
)

_FINISH_REASON_MAP = {
    "FINISH_REASON_STOP": "stop",
    "FINISH_REASON_MAX_TOKENS": "length",
    "FINISH_REASON_SAFETY": "safety",
    "FINISH_REASON_RECITATION": "content_filter",
    "FINISH_REASON_TOOL_CALL": "tool_calls",
}


def _notify_error(cb, message: str) -> None:
    if cb is None:
        return

    payload = SimpleNamespace(error=message)

    def runner() -> None:
        try:
            cb(payload, "error")
        except TypeError:
            cb(payload)

    try:
        ida_kernwin.execute_sync(runner, ida_kernwin.MFF_FAST)
    except Exception:
        runner()


def _to_plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_plain(v) for v in value]
    if isinstance(value, SimpleNamespace):
        return {k: _to_plain(v) for k, v in vars(value).items()}
    return value


def _safe_json(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}
        try:
            return json.loads(stripped)
        except Exception:
            return stripped
    return value


def _convert_tools(tools_spec: Iterable[Any] | None) -> list[types.Tool] | None:
    if not tools_spec:
        return None

    declarations: list[types.FunctionDeclaration] = []
    for tool in tools_spec:
        data = _to_plain(tool)
        if data.get("type") != "function":
            continue
        fn = data.get("function") or {}
        name = fn.get("name")
        if not name:
            continue
        declarations.append(
            types.FunctionDeclaration(
                name=name,
                description=fn.get("description"),
                parameters=fn.get("parameters"),
            )
        )

    if not declarations:
        return None

    return [types.Tool(function_declarations=declarations)]


def _as_text_part(text: str) -> types.Part:
    return types.Part.from_text(text=text)


def _convert_messages(query: Any) -> tuple[str | None, list[types.Content]]:
    if isinstance(query, str):
        query = [{"role": "user", "content": query}]

    system_lines: list[str] = []
    contents: list[types.Content] = []

    for raw in query or []:
        message = _to_plain(raw)
        role = (message.get("role") or "").lower()

        if role == "system":
            content = message.get("content")
            if content:
                system_lines.append(str(content))
            continue

        if role == "tool":
            name = message.get("name") or message.get("tool_call_id") or ""
            payload = _safe_json(message.get("content"))
            if not isinstance(payload, (dict, list)):
                payload = {"result": payload}
            contents.append(
                types.Content(
                    role="tool",
                    parts=[
                        types.Part.from_function_response(
                            name=name,
                            response=_to_plain(payload),
                        )
                    ],
                )
            )
            continue

        if role == "assistant":
            parts: list[types.Part] = []
            for part in message.get("parts") or message.get("gemini_parts") or []:
                part = _to_plain(part)
                if "text" in part:
                    parts.append(_as_text_part(str(part["text"])))
                elif "function_call" in part:
                    fc = _to_plain(part["function_call"])
                    args = _safe_json(fc.get("args"))
                    if not isinstance(args, dict):
                        args = {}
                    parts.append(
                        types.Part.from_function_call(
                            name=fc.get("name", ""),
                            args=_to_plain(args),
                        )
                    )
            text = message.get("content")
            if isinstance(text, str) and text:
                parts.append(_as_text_part(text))
            for tool_call in message.get("tool_calls") or []:
                call = _to_plain(tool_call)
                fn = _to_plain(call.get("function") or {})
                args = _safe_json(fn.get("arguments"))
                if not isinstance(args, dict):
                    args = {}
                parts.append(
                    types.Part.from_function_call(
                        name=fn.get("name", ""),
                        args=_to_plain(args),
                    )
                )
            if parts:
                contents.append(types.Content(role="model", parts=parts))
            continue

        parts: list[types.Part] = []
        for part in message.get("parts") or []:
            part = _to_plain(part)
            if isinstance(part, dict) and "text" in part:
                parts.append(_as_text_part(str(part["text"])))
            else:
                parts.append(_as_text_part(str(part)))
        if not parts:
            content = message.get("content")
            if isinstance(content, list):
                for item in content:
                    parts.append(_as_text_part(str(item)))
            elif content is not None:
                parts.append(_as_text_part(str(content)))
        if parts:
            contents.append(types.Content(role="user", parts=parts))

    system_instruction = "\n".join(system_lines) if system_lines else None
    return system_instruction, contents


def _convert_finish_reason(reason: Any, has_tool_calls: bool) -> str:
    if reason is None:
        return "tool_calls" if has_tool_calls else "stop"
    label = str(getattr(reason, "name", reason)).upper()
    if has_tool_calls and label in {"FINISH_REASON_STOP", "FINISH_REASON_UNSPECIFIED"}:
        return "tool_calls"
    return _FINISH_REASON_MAP.get(label, "tool_calls" if has_tool_calls else "stop")


class _ResponseBuilder:
    def __init__(self) -> None:
        self._text = ""
        self._tool_calls: dict[str, SimpleNamespace] = {}
        self._order: list[str] = []

    @property
    def content(self) -> str:
        return self._text

    def add_text(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return ""

        previous = self._text
        if text.startswith(previous):
            delta = text[len(previous):]
            if not delta:
                return ""
            self._text = previous + delta
            return delta

        self._text = text
        return text

    def add_tool_call(self, name: Any, args: Any, call_id: Any) -> tuple[SimpleNamespace, str, str]:
        call_id_str = str(call_id) if call_id else f"tool_call_{len(self._order)}"
        if call_id_str in self._tool_calls:
            call = self._tool_calls[call_id_str]
        else:
            call = SimpleNamespace(
                index=len(self._order),
                id=call_id_str,
                type="function",
                function=SimpleNamespace(name="", arguments=""),
            )
            self._tool_calls[call_id_str] = call
            self._order.append(call_id_str)

        name_delta = ""
        args_delta = ""

        if isinstance(name, str) and name:
            previous = call.function.name
            call.function.name = name
            if name.startswith(previous):
                name_delta = name[len(previous):]
            else:
                name_delta = name

        if args is not None:
            plain_args = _to_plain(args)
            if isinstance(plain_args, str):
                serialized = plain_args
            else:
                try:
                    serialized = json.dumps(plain_args, ensure_ascii=False)
                except TypeError:
                    serialized = json.dumps(plain_args, ensure_ascii=False, default=str)
            previous = call.function.arguments
            call.function.arguments = serialized
            if serialized.startswith(previous):
                args_delta = serialized[len(previous):]
            else:
                args_delta = serialized

        return call, name_delta, args_delta

    def has_tool_calls(self) -> bool:
        return bool(self._order)

    def build_message(self) -> SimpleNamespace:
        tool_calls: list[SimpleNamespace] = []
        for call_pos, call_id in enumerate(self._order):
            call = self._tool_calls[call_id]
            index = getattr(call, "index", call_pos)
            tool_calls.append(
                SimpleNamespace(
                    index=index,
                    id=call.id,
                    type=call.type,
                    function=SimpleNamespace(
                        name=call.function.name,
                        arguments=call.function.arguments,
                    ),
                )
            )
        return SimpleNamespace(
            content=self._text,
            tool_calls=tool_calls,
        )


class Gemini(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Google Gemini"

    @staticmethod
    def supported_models():
        return [
            GEMINI_FLASH_LATEST_MODEL_NAME,
            GEMINI_FLASH_LITE_LATEST_MODEL_NAME,
            GEMINI_2_0_FLASH_MODEL_NAME,
            GEMINI_2_5_PRO_MODEL_NAME,
            GEMINI_2_5_FLASH_MODEL_NAME,
        ]

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("Gemini", "API_KEY", "GEMINI_API_KEY"))

    def __init__(self, model_name):
        self.model_name = model_name
        api_key = gepetto.config.get_config("Gemini", "API_KEY", "GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                _("Please edit the configuration file to insert your {api_provider} API key!")
                .format(api_provider="Google Gemini")
            )

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        http_options = None
        if proxy:
            http_options = types.HttpOptions(
                client_args={"proxy": proxy},
                async_client_args={"proxy": proxy},
            )

        self.client = genai.Client(api_key=api_key, http_options=http_options)

    def __str__(self):
        return self.model_name

    def _prepare_call_kwargs(
        self,
        query: Any,
        additional_model_options: dict[str, Any] | None,
    ) -> dict[str, Any]:
        options = dict(additional_model_options or {})
        system_instruction, contents = _convert_messages(query)
        if not contents:
            raise ValueError("Gemini requires at least one message to generate a response.")

        response_format = options.pop("response_format", None)
        tools_spec = options.pop("tools", None)

        tools = _convert_tools(tools_spec)

        config_kwargs: dict[str, Any] = {
            "safety_settings": list(_DEFAULT_SAFETY_SETTINGS),
        }
        try:
            # Disable Gemini "thinking" stream to avoid spamming reasoning steps (for now).
            # This needs to be in a try/except for older genai SDKs that do not support it
            config_kwargs["thinking_config"] = types.ThinkingConfig(include_thoughts=False)
        except:
            pass
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction
        if tools:
            config_kwargs["tools"] = tools
        if isinstance(response_format, dict) and response_format.get("type") == "json_object":
            config_kwargs["response_mime_type"] = "application/json"

        config_override = options.pop("config", None)
        if config_override is None:
            config = types.GenerateContentConfig(**config_kwargs)
        elif isinstance(config_override, dict):
            merged = {**config_kwargs, **config_override}
            config = types.GenerateContentConfig(**merged)
        else:
            config = config_override

        call_kwargs = {
            "model": self.model_name,
            "contents": contents,
            "config": config,
        }

        return call_kwargs

    def _emit_parts(
        self,
        parts: Iterable[Any],
        builder: _ResponseBuilder,
        stream_cb=None,
    ) -> bool:
        emitted = False
        for part in parts:
            text = getattr(part, "text", None)
            if isinstance(text, str) and text:
                delta = builder.add_text(text)
                if stream_cb and delta:
                    stream_cb(delta, None)
                if delta:
                    emitted = True
                continue

            function_call = getattr(part, "function_call", None)
            if function_call:
                call, name_delta, args_delta = builder.add_tool_call(
                    getattr(function_call, "name", None),
                    getattr(function_call, "args", None),
                    getattr(function_call, "id", None),
                )
                if stream_cb and (name_delta or args_delta):
                    call_index = getattr(call, "index", None)
                    if call_index is None:
                        try:
                            call_index = builder._order.index(call.id)
                        except ValueError:
                            call_index = len(builder._order)
                        call.index = call_index
                    stream_cb(
                        SimpleNamespace(
                            tool_calls=[
                                SimpleNamespace(
                                    index=call_index,
                                    id=call.id,
                                    type=call.type,
                                    function=SimpleNamespace(
                                        name=name_delta,
                                        arguments=args_delta,
                                    ),
                                )
                            ]
                        ),
                        None,
                    )
                emitted = True

        return emitted

    def _ingest_response(self, response: Any, builder: _ResponseBuilder) -> Any:
        finish_reason = None
        for candidate in getattr(response, "candidates", None) or []:
            finish_reason = getattr(candidate, "finish_reason", finish_reason)
            content = getattr(candidate, "content", None)
            parts = getattr(content, "parts", None) or []
            if parts:
                if self._emit_parts(parts, builder):
                    continue

            text = getattr(content, "text", None)
            if isinstance(text, str) and text:
                builder.add_text(text)
        if not builder.content:
            text = getattr(response, "text", None)
            if isinstance(text, str) and text:
                builder.add_text(text)
        return finish_reason

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        try:
            call_kwargs = self._prepare_call_kwargs(query, additional_model_options)
            if stream:
                response_stream = self.client.models.generate_content_stream(**call_kwargs)
                builder = _ResponseBuilder()
                finish_reason = None
                for chunk in response_stream:
                    chunk_emitted = False
                    for candidate in getattr(chunk, "candidates", None) or []:
                        finish_reason = getattr(candidate, "finish_reason", finish_reason)
                        content = getattr(candidate, "content", None)
                        parts = getattr(content, "parts", None) or []
                        if parts:
                            if self._emit_parts(parts, builder, cb):
                                chunk_emitted = True
                            continue

                        text = getattr(content, "text", None)
                        if isinstance(text, str) and text:
                            delta = builder.add_text(text)
                            if delta:
                                if cb:
                                    cb(delta, None)
                                chunk_emitted = True

                    if not chunk_emitted:
                        text = getattr(chunk, "text", None)
                        if isinstance(text, str) and text:
                            delta = builder.add_text(text)
                            if delta:
                                if cb:
                                    cb(delta, None)
                                chunk_emitted = True
                final_reason = _convert_finish_reason(finish_reason, builder.has_tool_calls())
                cb(None, final_reason)
            else:
                response = self.client.models.generate_content(**call_kwargs)
                builder = _ResponseBuilder()
                self._ingest_response(response, builder)
                message = builder.build_message()
                ida_kernwin.execute_sync(
                    functools.partial(cb, response=message),
                    ida_kernwin.MFF_WRITE,
                )
        except Exception as exc:
            error_message = _("General exception encountered while running the query: {error}").format(error=str(exc))
            print(error_message)
            _notify_error(cb, error_message)

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        thread = threading.Thread(
            target=self.query_model,
            args=(query, cb, stream, additional_model_options),
            daemon=True,
        )
        thread.start()


gepetto.models.model_manager.register_model(Gemini)
