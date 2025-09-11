import functools
import re
import threading
from types import SimpleNamespace

import httpx as _httpx
import ida_kernwin
import openai

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

GPT_5_MODEL_NAME = "gpt-5"
GPT_5_MINI_MODEL_NAME = "gpt-5-mini"
GPT_5_NANO_MODEL_NAME = "gpt-5-nano"
GPT_5_HIGH_ALIAS = "gpt-5 (high)"
GPT4_MODEL_NAME = "gpt-4-turbo"
GPT4O_MODEL_NAME = "gpt-4o"
GPTO4_MINI_MODEL_NAME = "o4-mini"
GPT41_MODEL_NAME = "gpt-4.1"
GPTO3_MODEL_NAME = "o3"
GPTO3_MINI_MODEL_NAME = "o3-mini"
OPENAI_RESTRICTED_MODELS = [GPT_5_MODEL_NAME, GPT_5_MINI_MODEL_NAME, GPT_5_NANO_MODEL_NAME, GPTO3_MODEL_NAME]

class GPT(LanguageModel):
    # Default adapter is Chat Completions. The first‑party OpenAI provider
    # (this class) promotes itself to Responses API in __init__.
    use_responses_api: bool = False
    oai_org_unverified = False
    oai_restricted_models = OPENAI_RESTRICTED_MODELS

    @staticmethod
    def get_menu_name() -> str:
        return "OpenAI"

    @staticmethod
    def supported_models():
        return [# Convenience alias that forces high reasoning effort
                GPT_5_HIGH_ALIAS,
                GPT_5_MODEL_NAME,
                GPT_5_MINI_MODEL_NAME,
                GPT_5_NANO_MODEL_NAME,
                GPT4_MODEL_NAME,
                GPT4O_MODEL_NAME,
                GPTO4_MINI_MODEL_NAME,
                GPT41_MODEL_NAME,
                GPTO3_MODEL_NAME,
                GPTO3_MINI_MODEL_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY"))

    def __init__(self, model):
        # Display name (what UI shows / config stores)
        self.model = model
        # Map display name to actual API model name
        self.api_model = GPT_5_MODEL_NAME if model == GPT_5_HIGH_ALIAS else model
        self.reasoning_effort_override = "high" if model == GPT_5_HIGH_ALIAS else None
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
        # For the first‑party OpenAI provider, default to the Responses API.
        # Subclasses (OpenAI-compatible vendors) inherit False unless overridden.
        if self.__class__ is GPT:
            self.use_responses_api = True

    def __str__(self):
        return self.model

    # Helpers ---------------------------------------------------------------
    def _is_gpt5_family(self):
        try:
            return str(self.api_model).startswith("gpt-5")
        except Exception:
            return False

    def _build_responses_input(self, conversation):
        """Convert chat-style messages into Responses `instructions` and `input`.

        Ensures content parts use the correct `type` values like `input_text`.
        """
        # Combine any system messages into instructions; keep others as input items
        system_instructions = []
        input_items = []
        for msg in conversation:
            role = msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", None)
            content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            tool_calls = msg.get("tool_calls") if isinstance(msg, dict) else getattr(msg, "tool_calls", None)
            if role == "system":
                if content:
                    system_instructions.append(str(content))
                continue

            # Map Chat-style tool result messages to Responses FunctionCallOutput items
            if role == "tool":
                call_id = None
                for k in ("tool_call_id", "id"):
                    v = msg.get(k) if isinstance(msg, dict) else getattr(msg, k, None)
                    if v:
                        call_id = str(v)
                        break
                out = content
                if isinstance(out, (dict, list)):
                    try:
                        import json as _json
                        out = _json.dumps(out, ensure_ascii=False)
                    except Exception:
                        out = str(out)
                elif out is None:
                    out = ""
                input_items.append({
                    "type": "function_call_output",
                    "call_id": call_id or "",
                    "output": str(out),
                })
                continue

            item = {"role": role or "user"}

            # Normalize text content into Responses-style parts
            parts = []
            # Choose part type based on role: user/tool => input_text, assistant => output_text
            part_type = "output_text" if (role == "assistant") else "input_text"
            if isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and ("text" in p):
                        txt = p.get("text", "")
                        parts.append({"type": part_type, "text": txt})
                    elif isinstance(p, dict) and p.get("type") in ("input_text", "output_text"):
                        # Respect explicit type if the caller already matched schema
                        parts.append({"type": p.get("type"), "text": p.get("text", "")})
                    else:
                        parts.append({"type": part_type, "text": str(p)})
            elif isinstance(content, str):
                parts.append({"type": part_type, "text": content})
            elif content is None:
                pass
            else:
                parts.append({"type": part_type, "text": str(content)})

            # Include assistant-issued tool calls (function calls) so subsequent
            # tool results (function_call_output) can reference them by call_id.
            # Without echoing the function calls, the Responses API will reject
            # our tool outputs with: "No tool call found for function call output".
            if role == "assistant" and tool_calls:
                try:
                    for tc in tool_calls:
                        # Chat-style tool_calls: {id, type:"function", function:{name, arguments}}
                        if isinstance(tc, dict):
                            tc_id = tc.get("id") or ""
                            fn = tc.get("function") or {}
                            name = fn.get("name") or ""
                            args = fn.get("arguments") or ""
                        else:
                            tc_id = getattr(tc, "id", "")
                            fn = getattr(tc, "function", None)
                            name = getattr(fn, "name", "") if fn is not None else ""
                            args = getattr(fn, "arguments", "") if fn is not None else ""
                        # Append a function_call item; id is optional, call_id pairs with the output
                        input_items.append({
                            "type": "function_call",
                            "call_id": str(tc_id or ""),
                            "name": str(name or ""),
                            "arguments": str(args or ""),
                        })
                except Exception:
                    # Be permissive; at worst the tool outputs will be ignored by the model
                    pass

            if parts:
                item["content"] = parts

            input_items.append(item)

        instructions = "\n".join(system_instructions) if system_instructions else None
        return instructions, input_items

    def _to_chat_tools(self, tools: list | None):
        """Convert Responses-style tools to Chat Completions style."""
        if not tools:
            return None
        out = []
        for t in tools:
            if not isinstance(t, dict) or t.get("type") != "function":
                continue
            name = t.get("name")
            params = t.get("parameters") or {"type": "object"}
            desc = t.get("description")
            strict = t.get("strict")
            # Ensure strict-compatible JSON Schema subset: disallow unknown keys
            if strict and isinstance(params, dict):
                if params.get("type") == "object" and "additionalProperties" not in params:
                    params = dict(params)
                    params["additionalProperties"] = False
            fn = {"name": name, "parameters": params}
            if desc is not None:
                fn["description"] = desc
            if strict is not None:
                fn["strict"] = strict
            out.append({"type": "function", "function": fn})
        return out or None

    def _finalize_chat_to_pseudo_response(self, text: str, tool_calls: list[dict]):
        from types import SimpleNamespace
        output = []
        if text:
            output.append({
                "type": "output_text",
                "content": [{"text": text}],
            })
        for tc in tool_calls or []:
            output.append({
                "type": "tool_call",
                "id": tc.get("id", ""),
                "name": tc.get("function", {}).get("name", ""),
                "arguments": tc.get("function", {}).get("arguments", ""),
            })
        return SimpleNamespace(output=output)

    def _query_via_chat_completions(self, conversation, cb, stream, additional_model_options):
        # Prepare messages as-is; they are already Chat Completions-shaped
        messages = conversation

        # Prepare tools for Chat Completions
        opts = dict(additional_model_options or {})
        tools = self._to_chat_tools(opts.pop("tools", None))

        # Respect global parallel tool calls toggle if not explicitly set
        if "parallel_tool_calls" not in opts:
            try:
                ptc = gepetto.config.get_config("OpenAI", "PARALLEL_TOOL_CALLS", default="false")
                ptc_bool = str(ptc).strip().lower() in ("1", "true", "yes", "on")
            except Exception:
                ptc_bool = False
            opts["parallel_tool_calls"] = ptc_bool

        # Map response_format.json_object → response_format JSON schema minimal
        # Chat Completions accepts both json_object and json_schema nowadays.
        rf = opts.get("response_format")
        if isinstance(rf, dict) and rf.get("type") == "json_object":
            opts["response_format"] = {"type": "json_object"}

        try:
            if not stream:
                resp = self.client.chat.completions.create(
                    model=self.api_model,
                    messages=messages,
                    tools=tools,
                    **opts,
                )
                choice = resp.choices[0] if getattr(resp, "choices", None) else None
                text = (getattr(choice.message, "content", None) if choice else None) or ""
                tcs = getattr(choice.message, "tool_calls", None) or []
                pseudo = self._finalize_chat_to_pseudo_response(text, tcs)
                # Invoke callback directly from worker thread. UI updates inside
                # the callback (status panel, etc.) already use execute_sync
                # internally, and tool handlers may need to call execute_sync
                # themselves. Calling cb on the UI thread can deadlock when
                # tools then call execute_sync again.
                cb(response=pseudo)
                return
            else:
                stream_resp = self.client.chat.completions.create(
                    model=self.api_model,
                    messages=messages,
                    tools=tools,
                    stream=True,
                    **opts,
                )
                # Accumulate text and tool calls
                text_buf = []
                tool_calls = {}
                def upsert_tool_call(delta_tc):
                    idx = getattr(delta_tc, "index", None)
                    if idx is None:
                        return
                    entry = tool_calls.get(idx)
                    if not entry:
                        entry = {"id": getattr(delta_tc, "id", "") or "",
                                 "function": {"name": "", "arguments": ""}}
                        tool_calls[idx] = entry
                    fn = getattr(delta_tc, "function", None)
                    if fn is not None:
                        # name/arguments arrive incrementally
                        name = getattr(fn, "name", None)
                        args = getattr(fn, "arguments", None)
                        if name:
                            entry["function"]["name"] += name
                        if args:
                            entry["function"]["arguments"] += args

                for chunk in stream_resp:
                    ch = chunk.choices[0] if getattr(chunk, "choices", None) else None
                    delta = getattr(ch, "delta", None)
                    if delta is None:
                        continue
                    # Stream text
                    dtext = getattr(delta, "content", None)
                    if dtext:
                        text_buf.append(dtext)
                        cb(dtext, None)
                    # Collect tool call deltas
                    dtcs = getattr(delta, "tool_calls", None) or []
                    for dtc in dtcs:
                        upsert_tool_call(dtc)

                final_text = "".join(text_buf)
                tcs = [tool_calls[i] for i in sorted(tool_calls.keys())]
                pseudo = self._finalize_chat_to_pseudo_response(final_text, tcs)
                cb(response=pseudo)
                return
        except Exception as e:
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        """
        Send a request using the unified Responses API and call a callback as
        output arrives (streaming) or once the full response is ready.

        - `query` may be a string or a list of chat-like messages
        - `cb` is called as `cb(delta, finish_reason)` for streaming text deltas
          and once at the end as `cb(response=<Response>)` with the final object
        - Additional options may include `tools`, `tool_choice`, `max_tokens`,
          `response_format`, `reasoning`, etc. Mapped to Responses equivalents.
        """
        if additional_model_options is None:
            additional_model_options = {}

        # Build instructions and input from a chat-like conversation or a single string
        if isinstance(query, str):
            conversation = [{"role": "user", "content": query}]
        else:
            conversation = query

        # Route by API mode
        if not getattr(self, "use_responses_api", True):
            return self._query_via_chat_completions(conversation, cb, stream, additional_model_options)

        # Responses API path
        instructions, input_items = self._build_responses_input(conversation)

        # Map Chat options to Responses options
        opts = dict(additional_model_options or {})
        # response_format -> text.format
        text_opts = {}
        rf = opts.pop("response_format", None)
        if isinstance(rf, dict):
            if rf.get("type") == "json_object":
                text_opts["format"] = "json"
            elif rf.get("type") == "json_schema":
                # Minimal wrapper for JSON Schema in Responses
                js = rf.get("json_schema", {})
                name = js.get("name") or "Output"
                text_opts["format"] = {
                    "type": "json_schema",
                    "name": name,
                    "json_schema": {
                        "strict": True,
                        "schema": js.get("schema", {"type": "object"}),
                    },
                }
        if text_opts:
            opts["text"] = text_opts

        # max_tokens -> max_output_tokens
        if "max_tokens" in opts and "max_output_tokens" not in opts:
            try:
                opts["max_output_tokens"] = int(opts.pop("max_tokens"))
            except Exception:
                opts.pop("max_tokens", None)

        # Temperature guard for GPT‑5 family: omit or set to 1
        if self.api_model and str(self.api_model).startswith("gpt-5"):
            if "temperature" in opts and opts["temperature"] not in (None, 1):
                opts["temperature"] = 1

        # Always avoid server-side retention
        opts["store"] = False

        # Parallel tool calls: follow runtime config toggle if not explicitly set
        if "parallel_tool_calls" not in opts:
            try:
                ptc = gepetto.config.get_config("OpenAI", "PARALLEL_TOOL_CALLS", default="false")
                ptc_bool = str(ptc).strip().lower() in ("1", "true", "yes", "on")
            except Exception:
                ptc_bool = False
            opts["parallel_tool_calls"] = ptc_bool

        # Reasoning configuration: honor [OpenAI] reasoning_summary = off|auto|concise|detailed
        try:
            rs_mode = gepetto.config.get_config("OpenAI", "REASONING_SUMMARY", default="off")
        except Exception:
            rs_mode = "off"
        if isinstance(rs_mode, str) and rs_mode.lower() in {"auto", "concise", "detailed"}:
            # Only set for GPT‑5 / o‑series to avoid 400s on basic chat models
            if str(self.api_model).startswith("gpt-5") or str(self.api_model).startswith("o"):
                if "reasoning" not in opts:
                    effort = "medium" if rs_mode != "detailed" else "high"
                    opts["reasoning"] = {"summary": rs_mode.lower(), "effort": effort}
        # Apply explicit reasoning effort override from alias (e.g., GPT-5 (High))
        if self.reasoning_effort_override:
            r = opts.get("reasoning", {}) if isinstance(opts.get("reasoning"), dict) else {}
            r["effort"] = self.reasoning_effort_override
            opts["reasoning"] = r

        try:
            if not stream:
                resp = self.client.responses.create(
                    model=self.api_model,
                    input=input_items if len(input_items) > 0 else None,
                    instructions=instructions,
                    **opts,
                )
                # Call the callback directly from this worker thread. See notes
                # above regarding avoiding UI-thread deadlocks during tool calls.
                cb(response=resp)
                return
            else:
                # Streaming path
                # Use the streaming context manager for SSE and forward text deltas
                with self.client.responses.stream(
                    model=self.api_model,
                    input=input_items if len(input_items) > 0 else None,
                    instructions=instructions,
                    **opts,
                ) as stream_ctx:
                    sent_thinking = False
                    for event in stream_ctx:
                        etype = getattr(event, "type", None)
                        # Show a Thinking... status when any reasoning events begin
                        if (not sent_thinking) and isinstance(etype, str) and etype.startswith("response.reasoning"):
                            try:
                                cb({"status": "thinking"}, None)
                            except Exception:
                                pass
                            sent_thinking = True
                        # Stream textual output chunks
                        if etype == "response.output_text.delta":
                            delta = getattr(event, "delta", None)
                            if isinstance(delta, str) and delta:
                                cb(delta, None)
                        # End of textual output
                        elif etype == "response.output_text.done":
                            pass
                        else:
                            # Other event types are ignored here; tool calls will be surfaced in the final object
                            pass
                    final = stream_ctx.get_final_response()
                    cb(response=final)
                    return
        except openai.BadRequestError as e:
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            msg = _("Unfortunately, this function is too big to be analyzed with the model's current API limits.") if m else _("General exception encountered while running the query: {error}").format(error=str(e))
            try:
                cb(delta=None, finish_reason=f"error:{msg}")
            except Exception:
                pass
            print(msg)
        except openai.OpenAIError as e:
            msg = _("{model} could not complete the request: {error}").format(model=self.model, error=str(e))
            try:
                cb(delta=None, finish_reason=f"error:{msg}")
            except Exception:
                pass
            print(msg)
        except Exception as e:
            msg = _("General exception encountered while running the query: {error}").format(error=str(e))
            try:
                cb(delta=None, finish_reason=f"error:{msg}")
            except Exception:
                pass
            print(msg)

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

    # No additional internal helpers are required with Responses-first flow.

gepetto.models.model_manager.register_model(GPT)
