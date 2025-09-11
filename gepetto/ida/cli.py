from types import SimpleNamespace

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


class GepettoCLI(ida_kernwin.cli_t):
    flags = 0
    sname = "Gepetto"
    lname  = "Gepetto - " + _("LLM chat")
    hint = "Gepetto"

    def OnExecuteLine(self, line):
        if not line.strip():  # Don't do anything for empty sends.
            return True

        # Ensure status panel is visible and reflect current model
        try:
            STATUS.ensure_shown()
            STATUS.set_model(str(gepetto.config.model))
            STATUS.set_status("Waiting for model...", busy=True)
            STATUS.log(f"User: {line}")
        except Exception as e:
            try:
                print(f"Failed to make status panel visible: {e}")
            except Exception:
                pass

        MESSAGES.append({"role": "user", "content": line})

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

            def _response_reasoning_summary(resp):
                # Extract any reasoning summary text blocks from the response
                try:
                    data = resp.model_dump() if hasattr(resp, "model_dump") else {}
                    out = data.get("output") or []
                    summaries = []
                    for it in out:
                        if isinstance(it, dict) and it.get("type") == "reasoning":
                            for s in it.get("summary", []) or []:
                                if isinstance(s, dict) and isinstance(s.get("text"), str):
                                    summaries.append(s["text"])
                    if summaries:
                        return " ".join(summaries)
                except Exception:
                    pass
                return None

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
            reasoning_summary = _response_reasoning_summary(response)

            if tool_calls_ns:
                STATUS.set_status(f"Tool calls requested: {len(tool_calls_ns)}", busy=False)
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
                MESSAGES.append(
                    {
                        "role": "assistant",
                        "content": text or "",
                        "tool_calls": tool_calls,
                    }
                )
                for tc in tool_calls_ns:
                    STATUS.log(f"→ Tool: {tc.function.name}({(tc.function.arguments or '')[:120]}...)")
                    STATUS.set_status(f"Running tool: {tc.function.name}", busy=True)
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
                STATUS.end_stream()
                STATUS.set_status("Continuing after tools...", busy=True)
                stream_and_handle()
            else:
                # Ensure the streaming line is finished before logging summary
                try:
                    print("\n")
                except Exception:
                    pass
                STATUS.end_stream()
                if reasoning_summary:
                    STATUS.log(f"🧠 Reasoning summary: {reasoning_summary}")
                MESSAGES.append({"role": "assistant", "content": text or ""})
                STATUS.set_status("Done", busy=False)
                STATUS.log("✔ Completed turn")

        def stream_and_handle():
            message = SimpleNamespace(content="", tool_calls=[])
            model_name = str(gepetto.config.model)

            def on_chunk(delta=None, finish_reason=None, response=None):
                # Final Responses API object
                if response is not None:
                    try:
                        handle_response(response)
                    except Exception:
                        pass
                    return
                if isinstance(delta, dict) and delta.get("status") == "thinking":
                    STATUS.set_status("Thinking...", busy=True)
                    return
                if isinstance(delta, str):
                    # Stream to panel without newlines while printing to console.
                    STATUS.log_stream(delta, prefix=f"{model_name}: ")
                    print(delta, end="", flush=True)
                    message.content += delta
                    STATUS.set_status("Streaming...", busy=True)
                    return
                if isinstance(finish_reason, str) and finish_reason.startswith("error:"):
                    err = finish_reason.split(":", 1)[1] if ":" in finish_reason else finish_reason
                    print("\n")
                    STATUS.set_status("Error", busy=False)
                    STATUS.end_stream()
                    STATUS.log(f"✖ {err}")
                    return
                if finish_reason:
                    print("\n")
                    STATUS.set_status("Done", busy=False)
                    STATUS.end_stream()
                    STATUS.log("✔ Completed turn")

            gepetto.config.model.query_model_async(
                MESSAGES,
                on_chunk,
                stream=True,
                additional_model_options={"tools": TOOLS},
            )

        print()  # Add a line break before the model's response to improve readability
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
                print(f"Failed to set idle status in status panel: {e}")
            except Exception:
                pass
