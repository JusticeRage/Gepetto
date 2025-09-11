import functools
import re
import threading
from types import SimpleNamespace

import httpx as _httpx
import ida_kernwin
import openai
from pyexpat.errors import messages

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

GPT_5_MODEL_NAME = "gpt-5"
GPT_5_MINI_MODEL_NAME = "gpt-5-mini"
GPT_5_NANO_MODEL_NAME = "gpt-5-nano"
GPT4_MODEL_NAME = "gpt-4-turbo"
GPT4O_MODEL_NAME = "gpt-4o"
GPTO4_MINI_MODEL_NAME = "o4-mini"
GPT41_MODEL_NAME = "gpt-4.1"
GPTO3_MODEL_NAME = "o3"
GPTO3_MINI_MODEL_NAME = "o3-mini"
OPENAI_RESTRICTED_MODELS = [GPT_5_MODEL_NAME, GPT_5_MINI_MODEL_NAME, GPT_5_NANO_MODEL_NAME, GPTO3_MODEL_NAME]

class GPT(LanguageModel):
    oai_org_unverified = False
    oai_restricted_models = OPENAI_RESTRICTED_MODELS

    @staticmethod
    def get_menu_name() -> str:
        return "OpenAI"

    @staticmethod
    def supported_models():
        return [GPT_5_MODEL_NAME,
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

    def __str__(self):
        return self.model

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

        # Extract optional Responses API reasoning summary request if present in options
        # and/or via config. Chat Completions does not accept the `reasoning` param,
        # so remove it from the body we send to chat.completions and handle separately.
        reasoning_opts = None
        if "reasoning" in additional_model_options:
            try:
                # Keep a shallow copy to avoid mutating caller-provided dict
                reasoning_opts = dict(additional_model_options.get("reasoning") or {})
            except Exception:
                reasoning_opts = additional_model_options.get("reasoning")
            # Do not pass through to chat.completions
            try:
                del additional_model_options["reasoning"]
            except Exception:
                pass

        # Also allow enabling via config: [OpenAI] REASONING_SUMMARY = off|auto
        if reasoning_opts is None:
            try:
                cfg = gepetto.config.get_config("OpenAI", "REASONING_SUMMARY", default="off")
                if isinstance(cfg, str) and cfg.lower() in ("auto", "on", "true", "1"):
                    reasoning_opts = {"summary": "auto"}
            except Exception:
                pass
        # Guardrail: only attempt summaries on known-supported reasoning models to avoid
        # confusing/no-op outputs on others (e.g., printing just "detailed").
        supported_for_summary = {
            GPTO3_MODEL_NAME,
            GPTO3_MINI_MODEL_NAME,
            GPTO4_MINI_MODEL_NAME,
            GPT_5_MODEL_NAME,
            GPT_5_MINI_MODEL_NAME,
            GPT_5_NANO_MODEL_NAME,
        }
        if reasoning_opts and self.model not in supported_for_summary:
            reasoning_opts = None
        try:
            if type(query) is str:
                conversation = [
                    {"role": "user", "content": query}
                ]
            else:
                conversation = query

            def _request(_stream: bool):
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=conversation,
                    stream=_stream,
                    **additional_model_options
                )

            def _fallback():
                try:
                    # Retry without streaming, then adapt to streaming-like callbacks
                    response = _request(False)
                    message = response.choices[0].message
                    ida_kernwin.execute_sync(
                        functools.partial(cb, response=message),
                        ida_kernwin.MFF_WRITE,
                    )                    
                    # Emit content if any
                    if getattr(message, "content", None):
                        cb(message.content, None)
                    # Emit tool calls if any, in one go
                    tcs = getattr(message, "tool_calls", None) or []
                    if tcs:
                        tc_objs = []
                        for i, tc in enumerate(tcs):
                            fn = tc.function
                            tc_objs.append(
                                type("_TC", (), {
                                    "index": i,
                                    "id": getattr(tc, "id", ""),
                                    "type": getattr(tc, "type", "function"),
                                    "function": type("_FN", (), {
                                        "name": getattr(fn, "name", ""),
                                        "arguments": getattr(fn, "arguments", ""),
                                    })(),
                                })()
                            )
                        cb(type("_Delta", (), {"tool_calls": tc_objs})(), None)
                        cb(type("_Done", (), {})(), "tool_calls")
                    else:
                        cb(type("_Done", (), {})(), "stop")
                    return
                except Exception as e:
                    print(_("Exception encountered while retrying: {error}").format(error=str(e)))
                    # pass
            if self.oai_org_unverified and self.model in self.oai_restricted_models:
                _fallback()
            else:
                response = _request(stream)
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

                # After the streaming loop (or non-stream path above), optionally
                # fetch and emit a reasoning summary using the Responses API.
                if reasoning_opts:
                    def _emit_summary_async():
                        try:
                            summary_text = self._get_reasoning_summary(conversation, reasoning_opts)
                            if summary_text:
                                # Emit an out-of-band response object the CLI can pick up
                                ida_kernwin.execute_sync(
                                    functools.partial(cb, response=SimpleNamespace(reasoning_summary=summary_text)),
                                    ida_kernwin.MFF_WRITE,
                                )
                        except Exception:
                            # Be silent on summary failures; don't impact primary UX
                            pass

                    threading.Thread(target=_emit_summary_async, daemon=True).start()

        except openai.BadRequestError as e:
            # Fallback: some orgs/models do not allow streaming yet.
            if stream and ("stream" in str(e).lower() or "unsupported" in str(e).lower()):
                # if self.model in self.oai_restricted_models:
                print(_("Unable to query in streaming mode: {error}\nFalling back and retrying!").format(error=str(e)))
                self.oai_org_unverified = True
                try:
                    _fallback()
                    # Also try to fetch a reasoning summary if requested
                    if reasoning_opts:
                        def _emit_summary_async2():
                            try:
                                summary_text = self._get_reasoning_summary(conversation, reasoning_opts)
                                if summary_text:
                                    ida_kernwin.execute_sync(
                                        functools.partial(cb, response=SimpleNamespace(reasoning_summary=summary_text)),
                                        ida_kernwin.MFF_WRITE,
                                    )
                            except Exception:
                                pass
                        threading.Thread(target=_emit_summary_async2, daemon=True).start()
                    return
                except Exception as e:
                    print(_("Exception encountered while falling back: {error}").format(error=str(e)))
            # Context length exceeded. Determine the max number of tokens we can ask for and retry.
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            if m:
                print(_("Unfortunately, this function is too big to be analyzed with the model's current API limits."))
            else:
                print(_("General exception encountered while running the query: {error}").format(error=str(e)))
        except openai.OpenAIError as e:
            print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
        except Exception as e:
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))

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

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _get_reasoning_summary(self, conversation, reasoning_opts):
        """Best-effort retrieval of a reasoning summary using the Responses API.

        This does not alter the main request/response flow (which uses
        chat.completions for broad compatibility). We make a separate
        background call that asks the model to return its reasoning summary.

        :param conversation: List of message dicts (system/user/assistant/...)
        :param reasoning_opts: e.g., {"summary": "auto"}
        :return: string summary or None
        """
        # Build a simple transcript and extract any system instructions
        system_parts = []
        lines = []
        try:
            for m in conversation or []:
                role = m.get("role") if isinstance(m, dict) else getattr(m, "role", "")
                content = m.get("content") if isinstance(m, dict) else getattr(m, "content", "")
                if not content:
                    continue
                if role == "system":
                    system_parts.append(str(content))
                else:
                    lines.append(f"{role}: {content}")
        except Exception:
            pass

        instructions = "\n".join(system_parts) if system_parts else None
        transcript = "\n".join(lines) if lines else None
        if not transcript:
            return None

        # Call Responses API. We intentionally avoid passing tools/history to keep it robust
        # and request almost no assistant text to minimize latency/cost.
        try:
            resp = self.client.responses.create(
                model=self.model,
                input=transcript,
                instructions=instructions,
                reasoning=reasoning_opts,
                max_output_tokens=1,  # don't generate a second long answer
                parallel_tool_calls=False,
                store=False,
            )
        except Exception:
            return None

        # Extract textual reasoning summary from Responses output items.
        # Prefer the official shapes, then fall back to tolerant scanning.
        try:
            # Python SDK >= 1.98.0: resp.output contains Reasoning items with content/summary parts
            outputs = getattr(resp, "output", None) or []
            for item in outputs:
                # Match by attribute or dict shape
                itype = getattr(item, "type", None) or (item.get("type") if isinstance(item, dict) else None)
                if itype != "reasoning":
                    continue
                # Newer SDKs: item.content -> list of parts with .text and type 'reasoning_summary'
                parts = getattr(item, "content", None)
                if isinstance(parts, list):
                    for p in parts:
                        txt = getattr(p, "text", None) or (p.get("text") if isinstance(p, dict) else None)
                        if isinstance(txt, str) and txt.strip():
                            return txt.strip()
                # Older cookbook examples: item.summary -> list of parts with .text
                summary = getattr(item, "summary", None)
                if isinstance(summary, list):
                    for p in summary:
                        txt = getattr(p, "text", None) or (p.get("text") if isinstance(p, dict) else None)
                        if isinstance(txt, str) and txt.strip():
                            return txt.strip()
        except Exception:
            pass

        try:
            data = resp.model_dump() if hasattr(resp, "model_dump") else None
            if isinstance(data, dict):
                # Look specifically under output[*].(content|summary)[*].text to avoid
                # accidentally grabbing config values like {reasoning: {summary: "detailed"}}
                outs = data.get("output") if isinstance(data.get("output"), list) else []
                for item in outs:
                    if not isinstance(item, dict) or item.get("type") != "reasoning":
                        continue
                    for coll_key in ("content", "summary"):
                        coll = item.get(coll_key)
                        if isinstance(coll, list):
                            for p in coll:
                                txt = p.get("text") if isinstance(p, dict) else None
                                if isinstance(txt, str) and txt.strip():
                                    return txt.strip()
            return None
        except Exception:
            pass
        return None

    @staticmethod
    def _deep_find_text(data, keys=("text",)):
        """Recursively search for the first non-empty string value under any of the
        provided keys.
        """
        try:
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in keys and isinstance(v, str) and v.strip():
                        return v.strip()
                    res = GPT._deep_find_text(v, keys)
                    if res:
                        return res
            elif isinstance(data, list):
                for v in data:
                    res = GPT._deep_find_text(v, keys)
                    if res:
                        return res
        except Exception:
            return None
        return None

gepetto.models.model_manager.register_model(GPT)
