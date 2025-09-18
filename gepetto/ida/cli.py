from types import SimpleNamespace
import os

import ida_kernwin
import ida_idaapi

import gepetto.config
import gepetto.ida.handlers
from gepetto.ida.status_panel import panel as STATUS
from gepetto.ida.tools.tools import TOOLS
import gepetto.ida.tools.call_graph
import gepetto.ida.tools.get_ea
import gepetto.ida.tools.get_function_code
import gepetto.ida.tools.get_screen_ea
import gepetto.ida.tools.get_xrefs
import gepetto.ida.tools.list_symbols
import gepetto.ida.tools.refresh_view
import gepetto.ida.tools.rename_lvar
import gepetto.ida.tools.rename_function
import gepetto.ida.tools.search
import gepetto.ida.tools.to_hex
import gepetto.ida.tools.get_disasm
import gepetto.ida.tools.get_bytes

_ = gepetto.config._
CLI: ida_kernwin.cli_t = None
MESSAGES: list[dict] = [
    {
        "role": "system",
        "content":
            f"You are a helpful assistant embedded in IDA Pro. Your role is to facilitate "
            f"reverse-engineering and answer programming questions.\n"
            f"Your response should always be in the following locale: {gepetto.config.get_localization_locale()}\n"
            f"Never repeat pseudocode back as the user can see it already.\n"
            f"In the context of a reverse-engineering session, the user will switch from function to function a lot. "
            f"Between messages, don't assume that the function is still the same and always confirm it by checking the "
            f"current EA. \"This\" function or the \"current\" function always mean the one at the current EA.\n"
            f"When asked to perform an operation (such as renaming something), don't ask for confirmation. Just do it!\n"
            f"Always refresh the disassembly view after making a change in the IDB (renaming, etc.), so it is shown to"
            f"the user (no need to mention when you do it).\n"
            f"Addresses should always be shown as hex in the form 0x1234, but never convert decimal numbers to "
            f"hexadecimal yourself; always use the `to_hex` tool for that.\n"
            f"If you ever encounter a tool error, don't try again, print the exception and stop.",
    }
]  # Keep a history of the conversation to simulate LLM memory.

_SMOKE_TRACE = str(os.environ.get("GEPETTO_SMOKE_TRACE", "")).strip().lower() in {"1", "true", "yes", "on"}


class GepettoCLI(ida_kernwin.cli_t):
    flags = 0
    sname = "Gepetto"
    lname  = "Gepetto - " + _("LLM chat")
    hint = "Gepetto"

    def OnExecuteLine(self, line):
        import gepetto.config as _cfg
        provider = getattr(_cfg.model, "get_menu_name", lambda: _("Model"))()
        if not line.strip():  # Don't do anything for empty sends.
            return True

        # Ensure status panel is visible and reflect current model
        try:
            STATUS.ensure_shown()
            STATUS.set_model(str(gepetto.config.model))
            STATUS.set_status(_("Waiting for model..."), busy=True)
            # Reset stop state and bind backend cancellation to Stop button
            try:
                STATUS.reset_stop()
                STATUS.set_stop_callback(lambda: getattr(gepetto.config.model, "cancel_current_request", lambda: None)())
            except Exception:
                pass
            # Clear prior reasoning overlay at the start of each turn
            try:
                STATUS.clear_reasoning()
            except Exception:
                pass
            STATUS.log_user(line)
        except Exception as e:
            try:
                print(_("Failed to make status panel visible: {error}").format(error=e))
            except Exception:
                pass

        MESSAGES.append({"role": "user", "content": line})

        printed_any_text = False

        def handle_response(response):
            # Parse a Responses API Response into text and tool calls
            def _response_text(resp):
                txt = getattr(resp, "output_text", None)
                if isinstance(txt, str) and txt:
                    return txt
                data = resp.model_dump() if hasattr(resp, "model_dump") else None
                if isinstance(data, dict):
                    out = data.get("output")
                    if isinstance(out, list):
                        parts = []
                        for it in out:
                            if not isinstance(it, dict):
                                continue
                            if it.get("type") == "output_text":
                                content = it.get("content")
                                if isinstance(content, list):
                                    for p in content:
                                        t = p.get("text") if isinstance(p, dict) else None
                                        if isinstance(t, str):
                                            parts.append(t)
                                elif isinstance(it.get("text"), str):
                                    parts.append(it.get("text"))
                        if parts:
                            return "".join(parts)
                return ""

            def _response_tool_calls(resp):
                tc_list = []
                outputs = getattr(resp, "output", None)
                if isinstance(outputs, list) and outputs:
                    for idx, item in enumerate(outputs):
                        itype = getattr(item, "type", None) or (item.get("type") if isinstance(item, dict) else None)
                        # Responses emits function tool calls as type == "function_call"
                        if itype not in ("tool_call", "function_call"):
                            continue
                        iid = (
                            getattr(item, "id", None)
                            or getattr(item, "call_id", None)
                            or (item.get("id") if isinstance(item, dict) else None)
                            or (item.get("call_id") if isinstance(item, dict) else None)
                        )
                        name = getattr(item, "name", None) or (item.get("name") if isinstance(item, dict) else None)
                        args = getattr(item, "arguments", None) or (item.get("arguments") if isinstance(item, dict) else None)
                        tc_list.append(
                            SimpleNamespace(
                                index=idx,
                                id=iid or "",
                                type="function",
                                function=SimpleNamespace(name=name or "", arguments=args or ""),
                            )
                        )
                if not tc_list and hasattr(response, "model_dump"):
                    try:
                        data = response.model_dump()
                        outs = data.get("output") or []
                        for idx, it in enumerate(outs):
                            if isinstance(it, dict) and (it.get("type") in ("tool_call", "function_call")):
                                fn = it.get("name") or ""
                                args = it.get("arguments") or ""
                                iid = it.get("call_id") or it.get("id") or ""
                                tc_list.append(
                                    SimpleNamespace(
                                        index=idx,
                                        id=iid,
                                        type="function",
                                        function=SimpleNamespace(name=fn, arguments=args),
                                    )
                                )
                    except Exception:
                        pass
                return tc_list

            text = _response_text(response)
            tool_calls_ns = _response_tool_calls(response)
            if tool_calls_ns:
                # Close any ongoing styled reasoning summary stream before tool logs
                try:
                    STATUS.summary_stream_end()
                except Exception:
                    pass
                STATUS.set_status(_("Tool calls requested: {count}").format(count=len(tool_calls_ns)), busy=False)
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in tool_calls_ns
                ]
                msg = {
                    "role": "assistant",
                    "content": text or "",
                    "tool_calls": tool_calls,
                }
                MESSAGES.append(msg)
                for tc in tool_calls_ns:
                    STATUS.log(_("→ Tool: {tool_name}({tool_args}...)").format(tool_name=tc.function.name, tool_args=(tc.function.arguments or '')[:120]))
                    STATUS.set_status(_("Running tool: {tool_name}").format(tool_name=tc.function.name), busy=True)
                    if _SMOKE_TRACE:
                        try:
                            print(f"[TOOL] {tc.function.name}=start")
                        except Exception:
                            pass
                    if tc.function.name == "get_screen_ea":
                        gepetto.ida.tools.get_screen_ea.handle_get_screen_ea_tc(tc, MESSAGES)
                    elif tc.function.name == "get_ea":
                        gepetto.ida.tools.get_ea.handle_get_ea_tc(tc, MESSAGES)
                    elif tc.function.name == "get_function_code":
                        gepetto.ida.tools.get_function_code.handle_get_function_code_tc(tc, MESSAGES)
                    elif tc.function.name == "rename_lvar":
                        gepetto.ida.tools.rename_lvar.handle_rename_lvar_tc(tc, MESSAGES)
                    elif tc.function.name == "rename_function":
                        gepetto.ida.tools.rename_function.handle_rename_function_tc(tc, MESSAGES)
                    elif tc.function.name == "get_xrefs":
                        gepetto.ida.tools.get_xrefs.handle_get_xrefs_tc(tc, MESSAGES)
                    elif tc.function.name == "list_symbols":
                        gepetto.ida.tools.list_symbols.handle_list_symbols_tc(tc, MESSAGES)
                    elif tc.function.name == "list_strings":
                        gepetto.ida.tools.search.handle_list_strings_tc(tc, MESSAGES)
                    elif tc.function.name == "search":
                        gepetto.ida.tools.search.handle_search_tc(tc, MESSAGES)
                    elif tc.function.name == "to_hex":
                        gepetto.ida.tools.to_hex.handle_to_hex_tc(tc, MESSAGES)
                    elif tc.function.name == "get_disasm":
                        gepetto.ida.tools.get_disasm.handle_get_disasm_tc(tc, MESSAGES)
                    elif tc.function.name == "get_bytes":
                        gepetto.ida.tools.get_bytes.handle_get_bytes_tc(tc, MESSAGES)
                    elif tc.function.name == "get_callers":
                        gepetto.ida.tools.call_graph.handle_get_callers_tc(tc, MESSAGES)
                    elif tc.function.name == "get_callees":
                        gepetto.ida.tools.call_graph.handle_get_callees_tc(tc, MESSAGES)
                    elif tc.function.name == "refresh_view":
                        gepetto.ida.tools.refresh_view.handle_refresh_view_tc(tc, MESSAGES)
                    # Trace tool end with ok=… if available
                    if _SMOKE_TRACE:
                        try:
                            ok_val = None
                            for m in reversed(MESSAGES):
                                if m.get("role") == "tool" and m.get("tool_call_id") == tc.id:
                                    import json as _json
                                    try:
                                        payload = _json.loads(m.get("content") or "{}")
                                        if isinstance(payload, dict) and "ok" in payload:
                                            ok_val = payload.get("ok")
                                    except Exception:
                                        pass
                                    break
                            print(f"[TOOL] {tc.function.name}=end ok={ok_val if isinstance(ok_val, bool) else 'unknown'}")
                        except Exception:
                            pass
                STATUS.end_stream()
                if getattr(STATUS, "_stopped", False):
                    return
                STATUS.set_status(_("Continuing after tools..."), busy=True)
                stream_and_handle()
            else:
                # Ensure the streaming line is finished before logging summary
                try:
                    print("\n")
                except Exception:
                    pass
                STATUS.end_stream()

                try:
                    STATUS.summary_stream_end()
                except Exception:
                    pass
                # If we haven't streamed any assistant text yet but we have text
                # in the final response (common when streaming is disabled), print it now.
                if isinstance(text, str) and text.strip() and not printed_any_text:
                    try:
                        STATUS.answer_stream(text, str(gepetto.config.model))
                        print("\n")
                        STATUS.end_stream()
                    except Exception:
                        # Fall back to a simple log if styled stream fails
                        try:
                            STATUS.log(text)
                        except Exception:
                            pass
                final_msg = {"role": "assistant", "content": text or ""}
                MESSAGES.append(final_msg)
                STATUS.set_status("Done", busy=False)
                STATUS.clear_reasoning()
                STATUS.log(_("✔ Completed turn"))

        def stream_and_handle():
            message = SimpleNamespace(content="", tool_calls=[])
            model_name = str(gepetto.config.model)

            def on_chunk(delta, finish_reason):
                if isinstance(delta, str):
                    print(delta, end="", flush=True)
                    STATUS.answer_stream(delta, model_name)
                    message.content += delta
                    return
                if getattr(delta, "content", None):
                    print(delta.content, end="", flush=True)
                    # STATUS.log(delta.content)
                    STATUS.answer_stream(delta.content, model_name)
                    message.content += delta.content
                if getattr(delta, "tool_calls", None):
                    for tc in delta.tool_calls:
                        idx = tc.index
                        while len(message.tool_calls) <= idx:
                            message.tool_calls.append(
                                SimpleNamespace(
                                    id="",
                                    type="",
                                    function=SimpleNamespace(name="", arguments=""),
                                )
                            )
                        current = message.tool_calls[idx]
                        if getattr(tc, "id", None):
                            current.id = tc.id
                        if getattr(tc, "type", None):
                            current.type = tc.type
                        if getattr(tc, "function", None):
                            fn = tc.function
                            if getattr(fn, "name", None):
                                current.function.name += fn.name
                            if getattr(fn, "arguments", None):
                                current.function.arguments += fn.arguments
                if finish_reason:
                    if finish_reason != "tool_calls":
                        print("\n\n")  # Add a blank line after the model's reply for readability.
                    handle_response(message)

            gepetto.config.model.query_model_async(
                MESSAGES,
                on_chunk,
                stream=True,
                additional_model_options={"tools": TOOLS},
            )

        def stream_and_handle_gem():
            message = SimpleNamespace(content="", tool_calls=[])
            model_name = str(gepetto.config.model)

            def on_chunk(delta=None, finish_reason=None, response=None):
                nonlocal printed_any_text
                # Final Responses API object
                if response is not None:
                    try:
                        handle_response(response)
                    except Exception:
                        pass
                    return
                # Status/notice events from backends
                if isinstance(delta, dict) and delta.get("status") == "fallback":
                    try:
                        text = delta.get("text") or _("Streaming fallback activated: switching to non‑streaming mode. Latency may be higher and reasoning summaries will be disabled.")
                        STATUS.set_status(_("Fallback (no streaming)"), busy=True)
                        STATUS.log(text)
                    except Exception:
                        pass
                    return
                if isinstance(delta, dict) and delta.get("status") == "thinking":
                    try:
                        STATUS.summary_stream_start(model_name)
                    except Exception:
                        pass
                    STATUS.set_status(_("Reasoning..."), busy=True)
                    STATUS.set_reasoning(_("Reasoning"))
                    return
                if isinstance(delta, dict) and delta.get("status") == "notice":
                    try:
                        text = delta.get("text")
                        if isinstance(text, str) and text:
                            STATUS.log(text)
                    except Exception:
                        pass
                    # do not return; allow other handlers below to run if needed
                
                if isinstance(delta, str):
                    # Respect Stop: suppress console output and UI streaming when stopped
                    if getattr(STATUS, "_stopped", False):
                        return
                    printed_any_text = True
                    STATUS.answer_stream(delta, model_name)
                    print(delta, end="", flush=True)
                    message.content += delta
                    STATUS.set_status("Streaming...", busy=True)
                    return
                if isinstance(finish_reason, str) and finish_reason.startswith("error:"):
                    err = finish_reason.split(":", 1)[1] if ":" in finish_reason else finish_reason
                    print("\n")
                    STATUS.set_status(_("Error"), busy=False)
                    STATUS.end_stream()
                    STATUS.log(f"✖ {err}")
                    return
                if finish_reason:
                    print("\n")
                    try:
                        STATUS.summary_stream_end()
                    except Exception:
                        pass
                    STATUS.set_status("Done", busy=False)
                    STATUS.end_stream()
                    STATUS.log(_("✔ Completed turn"))


            gepetto.config.model.query_model_async(
                MESSAGES,
                on_chunk,
                stream=True,
                additional_model_options={"tools": TOOLS},
            )

        print()  # Add a line break before the model's response to improve readability
        if provider == "Google Gemini":
            stream_and_handle_gem()
        else:
            stream_and_handle()
        return True

    def OnKeydown(self, line, x, sellen, vkey, shift):
        pass

# -----------------------------------------------------------------------------

def cli_lifecycle_callback(code, old=0):
    if code == ida_idaapi.NW_OPENIDB:
        CLI.register()
    elif code == ida_idaapi.NW_CLOSEIDB or code == ida_idaapi.NW_TERMIDA:
        CLI.unregister()

# -----------------------------------------------------------------------------

def register_cli():
    global CLI
    if CLI:
        CLI.unregister()
        cli_lifecycle_callback(ida_idaapi.NW_TERMIDA)
    CLI = GepettoCLI()
    if CLI.register():
        ida_idaapi.notify_when(ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB, cli_lifecycle_callback)
        try:
            STATUS.ensure_shown()
            STATUS.set_status("Idle", busy=False)
        except Exception as e:
            try:
                print(_("Failed to set idle status in status panel: {error}").format(error=e))
            except Exception:
                pass
