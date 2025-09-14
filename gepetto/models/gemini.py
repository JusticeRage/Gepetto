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
            # Prefer raw Gemini parts if present to preserve thought signatures across turns
            raw_parts = _get(m, "parts") or _get(m, "gemini_parts")
            if isinstance(raw_parts, list) and raw_parts:
                gemini_messages.append({"role": "model", "parts": raw_parts})
                continue
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
            # Build a FunctionResponse payload per google-genai expectations
            # response must be an object with a 'content' list of parts
            tool_name = _get(m, "name", "")
            tool_id = _get(m, "tool_call_id", "") or _get(m, "id", "")
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = content

            # Gemini often expects: { name: <tool>, content: [{text: <json-or-text>}] }
            if isinstance(parsed, dict) and "content" in parsed:
                response_obj = parsed
            else:
                if isinstance(parsed, (dict, list)):
                    txt = json.dumps(parsed, ensure_ascii=False)
                else:
                    txt = str(parsed)
                response_obj = {
                    "name": tool_name,
                    "content": [{"text": txt}],
                }

            gemini_messages.append(
                {
                    "role": "user",
                    "parts": [
                        {
                            "function_response": {
                                "name": tool_name,
                                "id": tool_id,
                                "response": response_obj,
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
    """Convert our tool schema to Gemini `tools` list.

    Supports function tools and allows callers to pass native Gemini tools
    (e.g., {"google_search": {}}, {"code_execution": {}}, {"url_context": {}})
    alongside function declarations.
    """
    function_decls = []
    for t in tools or []:
        # Function tools (Chat Completions or Responses style)
        if _get(t, "type") != "function":
            continue
        # Accept both Chat Completions-style ({type:function, function:{...}})
        # and Responses-style ({type:function, name:"...", parameters:{...}})
        fn = _get(t, "function")
        if fn is not None:
            name = _get(fn, "name", "")
            desc = _get(fn, "description")
            params = _get(fn, "parameters")
        else:
            name = _get(t, "name", "")
            desc = _get(t, "description")
            params = _get(t, "parameters")
        if params:
            params = _sanitize_schema(params)
        try:
            function_decls.append(
                types.FunctionDeclaration(
                    name=name,
                    description=desc,
                    parameters=params,
                )
            )
        except Exception:
            # Fallback simple dict; the client may coerce this as needed
            function_decls.append({
                "name": name,
                "description": desc,
                "parameters": params,
            })
    if function_decls:
        return [types.Tool(function_declarations=function_decls)]
    return None


class Gemini(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return _("Google Gemini")

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
        # Cancellation primitives
        import threading as _thr
        self._cancel_lock = _thr.Lock()
        self._cancel_ev: _thr.Event | None = None
        self._active_stream = None

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

        # Enable Gemini "thinking" stream so we can display reasoning steps.
        # Latest docs recommend ThinkingConfig(include_thoughts=True) for
        # rolling, incremental summaries during generation.
        try:
            thinking_cfg = types.ThinkingConfig(include_thoughts=True)
        except Exception:
            thinking_cfg = None

        # Avoid duplicate keys from additional options
        additional_opts = dict(additional_model_options or {})
        additional_opts.pop("tools", None)

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=tools,
            safety_settings=safety_settings,
            thinking_config=thinking_cfg if thinking_cfg else None,
            **config_kwargs,
            **additional_opts,
        )

        try:
            if stream:
                response_stream = self.client.models.generate_content_stream(
                    model=self.model_name,
                    contents=messages,
                    config=config,
                )
                # Initialize/record cancel state for this request
                with self._cancel_lock:
                    import threading as _thr
                    self._cancel_ev = getattr(self, "_cancel_ev", None) or _thr.Event()
                    self._active_stream = response_stream

                # Accumulate tool calls across chunks to assign stable indices
                tool_idx_by_id: dict[str, int] = {}
                next_tool_index = 0
                pending_tool_calls: list = []
                saw_function_call = False
                text_buf: list[str] = []
                thought_buf: list[str] = []
                # Preserve original SDK part objects to keep thought_signature bytes intact
                raw_parts: list = []
                sent_reasoning_done = False

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

                sent_final = False
                for chunk in response_stream:
                    # Cancellation check
                    if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                        try:
                            close = getattr(response_stream, "close", None)
                            if callable(close):
                                close()
                        except Exception:
                            pass
                        with self._cancel_lock:
                            self._active_stream = None
                        break
                    parts = (
                        chunk.candidates[0].content.parts if chunk.candidates else []
                    )
                    finalize_on_function_call = False
                    for part in parts:
                        if getattr(part, "text", None):
                            # If this part carries Gemini thoughts, stream as reasoning summary
                            if getattr(part, "thought", False):
                                t = part.text or ""
                                t = t.rstrip("\r\n")  # avoid extra blank lines at end
                                if t:
                                    cb({"reasoning_summary_text_delta": t}, None)
                                    thought_buf.append(t)
                                    # Keep the raw part with signature
                                    raw_parts.append(part)
                            else:
                                # If normal text begins while we were still streaming thoughts,
                                # close the reasoning summary first to avoid interleaving.
                                if thought_buf and not sent_reasoning_done:
                                    try:
                                        cb({"reasoning_summary_done": "".join(thought_buf).rstrip("\r\n")}, None)
                                    except Exception:
                                        pass
                                    sent_reasoning_done = True
                                cb(part.text, None)
                                text_buf.append(part.text)
                                raw_parts.append(part)
                        elif getattr(part, "function_call", None):
                            upsert_tool_call(part.function_call)
                            raw_parts.append(part)
                            finalize_on_function_call = True

                    # If the model requested a tool call, finalize immediately; many backends pause here
                    if finalize_on_function_call and not sent_final:
                        output = []
                        final_text = "".join(text_buf)
                        if final_text:
                            output.append({
                                "type": "output_text",
                                "content": [{"text": final_text}],
                            })
                        final_thoughts = "".join(thought_buf).rstrip("\r\n")
                        if final_thoughts and not sent_reasoning_done:
                            try:
                                cb({"reasoning_summary_done": final_thoughts}, None)
                            except Exception:
                                pass
                            output.append({
                                "type": "reasoning",
                                "summary": [{"text": final_thoughts}],
                            })
                            sent_reasoning_done = True
                        for tc in pending_tool_calls:
                            output.append({
                                "type": "tool_call",
                                "id": tc.id,
                                "name": getattr(tc.function, "name", ""),
                                "arguments": getattr(tc.function, "arguments", ""),
                            })
                        if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                            with self._cancel_lock:
                                self._active_stream = None
                            return
                        cb(response=SimpleNamespace(output=output, gemini_parts=raw_parts, parts=raw_parts))
                        sent_final = True
                        try:
                            close = getattr(response_stream, "close", None)
                            if callable(close):
                                close()
                        except Exception:
                            pass
                        break

                    fr = chunk.candidates[0].finish_reason if chunk.candidates else None
                    if fr and getattr(types.FinishReason, "FINISH_REASON_UNSPECIFIED", None) is not None and fr != types.FinishReason.FINISH_REASON_UNSPECIFIED:
                        # Build a Responses-like final object so CLI can extract tool calls
                        output = []
                        final_text = "".join(text_buf)
                        if final_text:
                            output.append({
                                "type": "output_text",
                                "content": [{"text": final_text}],
                            })
                        # Emit reasoning summary done and include final summary in the object
                        final_thoughts = "".join(thought_buf).rstrip("\r\n")
                        if final_thoughts:
                            try:
                                cb({"reasoning_summary_done": final_thoughts}, None)
                            except Exception:
                                pass
                            output.append({
                                "type": "reasoning",
                                "summary": [{"text": final_thoughts}],
                            })
                        for tc in pending_tool_calls:
                            output.append({
                                "type": "tool_call",
                                "id": tc.id,
                                "name": getattr(tc.function, "name", ""),
                                "arguments": getattr(tc.function, "arguments", ""),
                            })
                        # Skip delivering final output if canceled
                        if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                            with self._cancel_lock:
                                self._active_stream = None
                            return
                        cb(response=SimpleNamespace(output=output, gemini_parts=raw_parts, parts=raw_parts))
                        sent_final = True
                # If the stream ended without an explicit finish_reason, flush what we have
                if not sent_final and (saw_function_call or text_buf or thought_buf or pending_tool_calls):
                    output = []
                    final_text = "".join(text_buf)
                    if final_text:
                        output.append({
                            "type": "output_text",
                            "content": [{"text": final_text}],
                        })
                    final_thoughts = "".join(thought_buf).rstrip("\r\n")
                    if final_thoughts and not sent_reasoning_done:
                        try:
                            cb({"reasoning_summary_done": final_thoughts}, None)
                        except Exception:
                            pass
                        output.append({
                            "type": "reasoning",
                            "summary": [{"text": final_thoughts}],
                        })
                        sent_reasoning_done = True
                    for tc in pending_tool_calls:
                        output.append({
                            "type": "tool_call",
                            "id": tc.id,
                            "name": getattr(tc.function, "name", ""),
                            "arguments": getattr(tc.function, "arguments", ""),
                        })
                    # Skip delivering final output if canceled
                    if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                        with self._cancel_lock:
                            self._active_stream = None
                        return
                    cb(response=SimpleNamespace(output=output, gemini_parts=raw_parts, parts=raw_parts))
            else:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=messages,
                    config=config,
                )

                message = SimpleNamespace(content="", tool_calls=[])
                final_thoughts = []
                raw_parts: list = []
                parts = (
                    response.candidates[0].content.parts if response.candidates else []
                )
                for part in parts:
                    if getattr(part, "text", None):
                        if getattr(part, "thought", False):
                            txt = (part.text or "").rstrip("\r\n")
                            final_thoughts.append(txt)
                            raw_parts.append(part)
                        else:
                            message.content += part.text
                            raw_parts.append(part)
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
                        raw_parts.append(part)

                if stream:
                    # Adapt to streaming-like callbacks: emit text deltas, then final response
                    if message.content:
                        cb(message.content, None)
                    if final_thoughts:
                        joined = "".join(final_thoughts).rstrip("\r\n")
                        cb({"reasoning_summary_done": joined}, None)
                    output = []
                    if message.content:
                        output.append({
                            "type": "output_text",
                            "content": [{"text": message.content}],
                        })
                    if final_thoughts:
                        output.append({
                            "type": "reasoning",
                            "summary": [{"text": "".join(final_thoughts).rstrip("\r\n")}],
                        })
                    for tc in message.tool_calls:
                        output.append({
                            "type": "tool_call",
                            "id": tc.id,
                            "name": getattr(tc.function, "name", ""),
                            "arguments": getattr(tc.function, "arguments", ""),
                        })
                    cb(response=SimpleNamespace(output=output, gemini_parts=raw_parts, parts=raw_parts))
                else:
                    # Non-streaming: deliver a final Responses-like object directly
                    output = []
                    if message.content:
                        output.append({
                            "type": "output_text",
                            "content": [{"text": message.content}],
                        })
                    if final_thoughts:
                        output.append({
                            "type": "reasoning",
                            "summary": [{"text": "".join(final_thoughts).rstrip("\r\n")}],
                        })
                    for tc in message.tool_calls:
                        output.append({
                            "type": "tool_call",
                            "id": tc.id,
                            "name": getattr(tc.function, "name", ""),
                            "arguments": getattr(tc.function, "arguments", ""),
                        })
                    cb(response=SimpleNamespace(output=output, gemini_parts=raw_parts, parts=raw_parts))

        except Exception as e:
            # Suppress network/stream errors if the request was cancelled
            try:
                if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                    with self._cancel_lock:
                        self._active_stream = None
                    return
            except Exception:
                pass
            error_message = _(
                "General exception encountered while running the query: {error}"
            ).format(error=str(e))
            print(error_message)

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        t = threading.Thread(
            target=self.query_model, args=[query, cb, stream, additional_model_options]
        )
        t.start()


    def cancel_current_request(self):
        """Signal cancellation to any in‑flight streaming request."""
        try:
            with self._cancel_lock:
                ev = getattr(self, "_cancel_ev", None)
                st = getattr(self, "_active_stream", None)
                if ev is not None:
                    ev.set()
                if st is not None:
                    try:
                        close = getattr(st, "close", None)
                        if callable(close):
                            close()
                    except Exception:
                        pass
                self._active_stream = None
        except Exception:
            pass

gepetto.models.model_manager.register_model(Gemini)
