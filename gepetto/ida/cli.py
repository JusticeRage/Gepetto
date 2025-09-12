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
                print(f"Failed to make status panel visible: {e}")
            except Exception:
                pass

        MESSAGES.append({"role": "user", "content": line})

        streamed_summary_seen = False

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
                # Close any ongoing styled reasoning summary stream before tool logs
                try:
                    STATUS.summary_stream_end()
                except Exception:
                    pass
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
                if getattr(STATUS, "_stopped", False):
                    return
                STATUS.set_status("Continuing after tools...", busy=True)
                stream_and_handle()
            else:
                # Ensure the streaming line is finished before logging summary
                try:
                    print("\n")
                except Exception:
                    pass
                STATUS.end_stream()
                if reasoning_summary and not streamed_summary_seen:
                    # Ensure any prior streaming line is finished, then log final summary in main output
                    try:
                        STATUS.end_stream()
                    except Exception:
                        pass
                    STATUS.log(f"Thinking Summary: {reasoning_summary}")
                try:
                    STATUS.summary_stream_end()
                except Exception:
                    pass
                MESSAGES.append({"role": "assistant", "content": text or ""})
                STATUS.set_status("Done", busy=False)
                STATUS.clear_reasoning()
                STATUS.log("✔ Completed turn")

        def stream_and_handle():
            message = SimpleNamespace(content="", tool_calls=[])
            model_name = str(gepetto.config.model)
            summary_text_started = False
            # Extract a concise heading for the reasoning strip from reasoning_text
            # or, if absent, from the first line / **Header** of the summary stream.
            heading_buf = ""
            current_heading = None
            last_heading_title = None  # without ellipsis
            summary_buffer = ""

            def _maybe_update_heading(delta_text: str, md_only: bool = False, finalize: bool = False):
                """Update the compact reasoning header.

                Behavior:
                - Prefer a Markdown header of the form "**Title**" at the very start.
                  If an opening "**" is seen, wait until the closing "**" before updating
                  (avoids truncated "Anal...").
                - If `md_only` is False, fall back to the first non-empty line,
                  but only after we have a newline (i.e., the line is complete),
                  or when `finalize` is True (e.g., on reasoning_text_done).
                - Caps length and appends an ellipsis to indicate streaming.
                """
                nonlocal heading_buf, current_heading, last_heading_title
                if not isinstance(delta_text, str) or not delta_text:
                    return
                heading_buf += delta_text
                try:
                    import re as _re
                    # 1) Strict Markdown header at the beginning
                    # If we detect an opening ** but not a closing yet, do not update.
                    if _re.match(r"^\s*\*\*", heading_buf):
                        m = _re.match(r"^\s*\*\*([^\*][^\*]{0,160})\*\*", heading_buf)
                        if not m:
                            # waiting for closing **; do nothing yet
                            return
                        title = (m.group(1) or "").strip()
                    else:
                        title = None
                        if not md_only:
                            # 2) Fallback: use first non-empty line, but only when we have a full line
                            if "\n" in heading_buf or finalize:
                                for line in heading_buf.splitlines():
                                    s = line.strip()
                                    if s:
                                        title = s[:160]
                                        break
                            else:
                                # Keep buffering until newline to avoid partial words
                                return
                    if title:
                        last_heading_title = title
                        # Cap shown length for the mini strip
                        if len(title) > 80:
                            title = title[:77] + " (...)"
                        shown = title if title.endswith("(...)") else f"{title}"
                        if shown != current_heading:
                            try:
                                STATUS.set_reasoning(shown)
                            except Exception:
                                pass
                            current_heading = shown
                except Exception:
                    pass

            def _strip_summary_header(text: str) -> str:
                """Remove duplicated header from the start of the summary text.

                Behavior:
                - If a Markdown header begins ("**Title") but the closing "**"
                  hasn't arrived yet, return "" to continue buffering.
                - If a full Markdown header is present, strip it and any
                  following blank lines.
                - If the first line equals the last parsed heading title
                  (non-markdown), strip that line.
                - Otherwise, return the text unchanged.
                """
                if not isinstance(text, str) or not text:
                    return text or ""
                import re as _re

                s = text
                ls = s.lstrip()
                if ls.startswith("**"):
                    # Incomplete Markdown header? keep buffering.
                    close = ls.find("**", 2)
                    if close == -1 and "\n" not in ls:
                        return ""
                    # If we have a closing **, strip header and any trailing newlines
                    if close != -1:
                        after = ls[close + 2 :]
                        after = after.lstrip(" \t\r\n")
                        # Map back to original string offset by the amount stripped from left
                        stripped_count = len(s) - len(ls)
                        s = s[:stripped_count] + after
                    else:
                        # Header line broken across lines: treat first line as header; strip it
                        first_line, sep, rest = s.partition("\n")
                        if sep:
                            s = rest.lstrip(" \t\r\n")
                        else:
                            return ""  # only header so far

                # Non-markdown header duplication: drop if equals last heading
                if last_heading_title:
                    first_line, sep, rest = s.partition("\n")
                    def _clean_title(t: str) -> str:
                        return t.strip().strip('*').rstrip(':').strip()
                    if _clean_title(first_line) == _clean_title(last_heading_title):
                        s = rest.lstrip(" \t\r\n") if sep else ""

                return s

            def on_chunk(delta=None, finish_reason=None, response=None):
                nonlocal summary_text_started, summary_buffer
                # Final Responses API object
                if response is not None:
                    try:
                        handle_response(response)
                    except Exception:
                        pass
                    return
                if isinstance(delta, dict) and delta.get("status") == "thinking":
                    # try:
                    #     STATUS.summary_stream_start(model_name)
                    # except Exception:
                    #     pass
                    STATUS.set_status("Reasoning...", busy=True)
                    STATUS.set_reasoning("Reasoning")
                    return
                # OpenAI Responses: live reasoning UI updates
                if isinstance(delta, dict):
                    rt = delta.get("reasoning_text_delta")
                    if isinstance(rt, str) and rt:
                        # Avoid partial updates; prefer full **header** or wait for newline.
                        _maybe_update_heading(rt, md_only=False, finalize=False)
                        return
                    rtd = delta.get("reasoning_text_done")
                    if isinstance(rtd, str):
                        # On completion, allow fallback extraction even without newline
                        _maybe_update_heading(rtd, md_only=False, finalize=True)
                        return
                    nonlocal streamed_summary_seen
                    # Stream mid-step summary parts and the final coherent summary into the main log
                    # rspd = delta.get("reasoning_summary_part_delta") or delta.get("reasoning_summary_part")
                    # if isinstance(rspd, str) and rspd:
                    #     # Heuristic: new step headers often begin with **Title**
                    #     if rspd.lstrip().startswith("**"):
                    #         # New step starting: reset heading parse and any ongoing summary stream
                    #         heading_buf = ""
                    #         if summary_text_started:
                    #             STATUS.end_stream()
                    #             summary_text_started = False
                    #         summary_buffer = ""
                    #     # For summary parts, only update when a complete **header** is present
                    #     _maybe_update_heading(rspd, md_only=True)
                    #     STATUS.log_stream(rspd, prefix="Reasoning: ")
                    #     streamed_summary_seen = True
                    #     return
                    rstd = delta.get("reasoning_summary_text_delta")
                    if isinstance(rstd, str) and rstd:
                        # If a new summary step begins while we were already streaming, restart
                        if summary_text_started and (rstd.lstrip().startswith("**") or (last_heading_title and rstd.strip().startswith(last_heading_title))):
                            STATUS.end_stream()
                            summary_text_started = False
                            summary_buffer = ""
                            heading_buf = ""
                        # Accumulate until we can safely strip header and start printing.
                        # Feed every delta into the header parser; it will update once **...** closes.
                        _maybe_update_heading(rstd, md_only=True)
                        summary_buffer += rstd
                        if not summary_text_started:
                            stripped = _strip_summary_header(summary_buffer)
                            # Start streaming once we have something meaningful after header
                            if stripped:
                                STATUS.end_stream()
                                summary_text_started = True
                                STATUS.summary_stream_start(model_name)
                                STATUS.summary_stream(stripped)
                                # STATUS.log_stream(stripped, prefix="Reasoning: ")
                                summary_buffer = ""
                        else:
                            STATUS.summary_stream(rstd)
                        streamed_summary_seen = True
                        return
                    rsd = delta.get("reasoning_summary_done")
                    if isinstance(rsd, str):
                        # If we buffered but never started streaming, flush now after stripping header
                        if not summary_text_started and summary_buffer:
                            stripped = _strip_summary_header(summary_buffer)
                            if stripped:
                                STATUS.summary_stream_start(model_name)
                                STATUS.summary_stream(stripped)
                        STATUS.summary_stream_end()
                        # Reset header accumulator at the end of a summary block
                        heading_buf = ""
                        summary_buffer = ""
                        summary_text_started = False
                        streamed_summary_seen = True
                        return
                if isinstance(delta, str):
                    # Respect Stop: suppress console output and UI streaming when stopped
                    if getattr(STATUS, "_stopped", False):
                        return
                    STATUS.answer_stream(delta, model_name)
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
                    try:
                        STATUS.summary_stream_end()
                    except Exception:
                        pass
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
