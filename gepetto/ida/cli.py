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
            if hasattr(response, "tool_calls") and response.tool_calls:
                STATUS.set_status(f"Tool calls requested: {len(response.tool_calls)}", busy=False)
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in response.tool_calls
                ]
                MESSAGES.append(
                    {
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": tool_calls,
                    }
                )
                for tc in response.tool_calls:
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
                    # Stream tool result content to the status panel (respecting Verbose)
                    # try:
                    #     # Find the tool response we just appended
                    #     tool_msg = None
                    #     for m in reversed(MESSAGES):
                    #         if isinstance(m, dict) and m.get("role") == "tool" and m.get("tool_call_id") == tc.id:
                    #             tool_msg = m
                    #             break
                    #     if tool_msg:
                    #         content = tool_msg.get("content") or ""
                    #         prefix = f"→ {tc.function.name}: "
                    #         # Truncate very large payloads to keep UI responsive
                    #         MAX_CHARS = 8192
                    #         truncated = False
                    #         if len(content) > MAX_CHARS:
                    #             content_to_show = content[:MAX_CHARS]
                    #             truncated = True
                    #         else:
                    #             content_to_show = content
                    #         # Chunk into smaller inserts for UI smoothness
                    #         CHUNK = 512
                    #         for i in range(0, len(content_to_show), CHUNK):
                    #             STATUS.log_stream(content_to_show[i:i+CHUNK], prefix=prefix)
                    #             prefix = ""  # ensure prefix only on first chunk
                    #         if truncated:
                    #             STATUS.log_stream("\n… (truncated)", prefix="")
                    #         STATUS.end_stream()
                    # except Exception:
                    #     pass
                STATUS.set_status("Continuing after tools...", busy=True)
                stream_and_handle()
            else:
                MESSAGES.append({"role": "assistant", "content": response.content or ""})

        def stream_and_handle():
            message = SimpleNamespace(content="", tool_calls=[])
            model_name = str(gepetto.config.model)

            def on_chunk(delta=None, finish_reason=None, response=None):
                # Handle out-of-band full responses or extras (e.g., reasoning summary)
                if response is not None:
                    try:
                        if hasattr(response, "reasoning_summary") and response.reasoning_summary:
                            STATUS.log(f"🧠 Reasoning: {response.reasoning_summary}")
                            return
                    except Exception:
                        pass
                    try:
                        handle_response(response)
                    except Exception:
                        pass
                    return
                if isinstance(delta, str):
                    # Stream to panel without newlines while printing to console.
                    STATUS.log_stream(delta, prefix=f"{model_name}: ")
                    print(delta, end="", flush=True)
                    message.content += delta
                    STATUS.set_status("Streaming...", busy=True)
                    return
                if getattr(delta, "content", None):
                    # Stream to panel without newlines while printing to console.
                    STATUS.log_stream(delta.content, prefix=f"{model_name}: ")
                    print(delta.content, end="", flush=True)
                    message.content += delta.content
                    STATUS.set_status("Streaming...", busy=True)
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
                    STATUS.set_status("Requesting tools...", busy=False)
                if finish_reason:
                    if finish_reason != "tool_calls":
                        print("\n")  # Add a blank line after the model's reply for readability.
                        STATUS.set_status("Done", busy=False)
                        # End streaming line in status panel
                        STATUS.end_stream()
                        STATUS.log("✔ Completed turn")
                    else:
                        # We are about to execute tools. End streaming line once.
                        STATUS.end_stream()
                    handle_response(message)

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
