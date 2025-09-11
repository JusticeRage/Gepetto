import functools
import json
import threading
from types import SimpleNamespace

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
GEMINI_2_5_FLASH_LITE_PREVIEW_MODEL_NAME = "gemini-2.5-flash-lite-preview-06-17"


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _convert_messages(messages):
    system_instruction = None
    gemini_messages = []
    for m in messages:
        role = _get(m, "role")
        content = _get(m, "content", "")
        if role == "system":
            system_instruction = (
                f"{system_instruction}\n{content}" if system_instruction else content
            )
            continue
        if role == "user":
            gemini_messages.append({"role": "user", "parts": [{"text": content}]})
        elif role == "assistant":
            parts = []
            if content:
                parts.append({"text": content})
            for tc in _get(m, "tool_calls", []):
                fn = _get(tc, "function", {})
                arguments = _get(fn, "arguments", "")
                try:
                    arguments = json.loads(arguments) if arguments else {}
                except json.JSONDecodeError:
                    arguments = {}
                parts.append(
                    {
                        "function_call": {
                            "name": _get(fn, "name", ""),
                            "args": arguments,
                            "id": _get(tc, "id", ""),
                        }
                    }
                )
            gemini_messages.append({"role": "model", "parts": parts})
        elif role == "tool":
            try:
                response = json.loads(content)
            except Exception:
                response = content
            gemini_messages.append(
                {
                    "role": "user",
                    "parts": [
                        {
                            "function_response": {
                                "name": _get(m, "name", ""),
                                "response": response,
                            }
                        }
                    ],
                }
            )
    return system_instruction, gemini_messages


_ALLOWED_SCHEMA_KEYS = {
    "type",
    "format",
    "description",
    "enum",
    "properties",
    "required",
    "items",
}


def _sanitize_schema(schema):
    if isinstance(schema, dict):
        cleaned = {}
        for k, v in schema.items():
            if k not in _ALLOWED_SCHEMA_KEYS:
                continue
            if k == "properties" and isinstance(v, dict):
                props = {}
                for pk, pv in v.items():
                    sanitized = _sanitize_schema(pv)
                    if sanitized:
                        props[pk] = sanitized
                if props:
                    cleaned["properties"] = props
                continue
            if k == "items":
                sanitized = _sanitize_schema(v)
                if sanitized:
                    cleaned["items"] = sanitized
                continue
            if k == "required" and isinstance(v, list):
                cleaned["required"] = list(v)
                continue
            sanitized = _sanitize_schema(v)
            if sanitized is not None:
                cleaned[k] = sanitized
        if "required" in cleaned:
            if "properties" in cleaned:
                cleaned["required"] = [r for r in cleaned["required"] if r in cleaned["properties"]]
                if not cleaned["required"]:
                    cleaned.pop("required")
            else:
                cleaned.pop("required")
        return cleaned or None
    if isinstance(schema, list):
        sanitized_list = []
        for v in schema:
            sanitized = _sanitize_schema(v)
            if sanitized is not None:
                sanitized_list.append(sanitized)
        return sanitized_list or None
    return schema


def _to_serializable(value):
    if isinstance(value, dict):
        return {k: _to_serializable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_serializable(v) for v in value]
    return value


def _convert_tools(tools):
    function_decls = []
    for t in tools or []:
        if _get(t, "type") != "function":
            continue
        fn = _get(t, "function", {})
        params = _get(fn, "parameters")
        if params:
            params = _sanitize_schema(params)
        function_decls.append(
            types.FunctionDeclaration(
                name=_get(fn, "name", ""),
                description=_get(fn, "description"),
                parameters=params,
            )
        )
    if function_decls:
        return [types.Tool(function_declarations=function_decls)]
    return None


class Gemini(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Google Gemini"

    @staticmethod
    def supported_models():
        return [
            GEMINI_2_0_FLASH_MODEL_NAME,
            GEMINI_2_5_PRO_MODEL_NAME,
            GEMINI_2_5_FLASH_MODEL_NAME,
            GEMINI_2_5_FLASH_LITE_PREVIEW_MODEL_NAME,
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

        self.client = genai.Client(api_key=api_key)

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        if proxy:
            print(
                _(
                    "Proxy configuration for Gemini via google-genai library might require manual setup of HTTPS_PROXY environment variable."
                )
            )

    def __str__(self):
        return self.model_name

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        config_kwargs = {}
        if (
            "response_format" in additional_model_options
            and additional_model_options["response_format"].get("type") == "json_object"
        ):
            config_kwargs["response_mime_type"] = "application/json"
            del additional_model_options["response_format"]

        system_instruction, messages = _convert_messages(
            [{"role": "user", "content": query}] if isinstance(query, str) else query
        )

        tools = None
        if "tools" in additional_model_options:
            tools = _convert_tools(additional_model_options.pop("tools"))

        safety_settings = [
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
        ]

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=tools,
            safety_settings=safety_settings,
            **config_kwargs,
            **additional_model_options,
        )

        try:
            if stream:
                response_stream = self.client.models.generate_content_stream(
                    model=self.model_name,
                    contents=messages,
                    config=config,
                )

                # Accumulate tool calls across chunks to assign stable indices
                tool_idx_by_id: dict[str, int] = {}
                next_tool_index = 0
                pending_tool_calls: list = []
                saw_function_call = False

                def upsert_tool_call(fc_obj):
                    nonlocal next_tool_index, saw_function_call
                    saw_function_call = True
                    fc_id = _get(fc_obj, "id", "") or f"auto_{next_tool_index}"
                    if fc_id not in tool_idx_by_id:
                        tool_idx_by_id[fc_id] = next_tool_index
                        next_tool_index += 1
                        pending_tool_calls.append(
                            SimpleNamespace(
                                index=tool_idx_by_id[fc_id],
                                id=fc_id,
                                type="function",
                                function=SimpleNamespace(name="", arguments=""),
                            )
                        )
                    idx = tool_idx_by_id[fc_id]
                    call = next(tc for tc in pending_tool_calls if tc.index == idx)
                    name = _get(fc_obj, "name", "") or ""
                    args = _to_serializable(_get(fc_obj, "args", {})) or {}
                    # Assign full values (avoid incremental duplication)
                    call.function.name = name
                    try:
                        call.function.arguments = json.dumps(args)
                    except Exception:
                        call.function.arguments = json.dumps(_to_serializable(args) or {})

                for chunk in response_stream:
                    parts = (
                        chunk.candidates[0].content.parts if chunk.candidates else []
                    )
                    for part in parts:
                        if getattr(part, "text", None):
                            cb(part.text, None)
                        elif getattr(part, "function_call", None):
                            upsert_tool_call(part.function_call)

                    fr = chunk.candidates[0].finish_reason if chunk.candidates else None
                    if fr and fr != types.FinishReason.FINISH_REASON_UNSPECIFIED:
                        # Emit pending tool calls (if any) before signaling finish
                        if pending_tool_calls:
                            cb(SimpleNamespace(tool_calls=pending_tool_calls), None)

                        finish_reason = fr.name.lower()
                        if finish_reason == "stop" and saw_function_call:
                            finish_reason = "tool_calls"
                        cb(SimpleNamespace(), finish_reason)
            else:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=messages,
                    config=config,
                )

                message = SimpleNamespace(content="", tool_calls=[])
                parts = (
                    response.candidates[0].content.parts if response.candidates else []
                )
                for part in parts:
                    if getattr(part, "text", None):
                        message.content += part.text
                    elif getattr(part, "function_call", None):
                        fc = part.function_call
                        message.tool_calls.append(
                            SimpleNamespace(
                                id=_get(fc, "id", ""),
                                type="function",
                                function=SimpleNamespace(
                                    name=_get(fc, "name", ""),
                                    arguments=json.dumps(
                                        _to_serializable(_get(fc, "args", {})) or {}
                                    ),
                                ),
                            )
                        )

                ida_kernwin.execute_sync(
                    functools.partial(cb, response=message),
                    ida_kernwin.MFF_WRITE,
                )

        except Exception as e:
            error_message = _(
                "General exception encountered while running the query: {error}"
            ).format(error=str(e))
            print(error_message)

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        t = threading.Thread(
            target=self.query_model, args=[query, cb, stream, additional_model_options]
        )
        t.start()


gepetto.models.model_manager.register_model(Gemini)
