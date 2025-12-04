from types import SimpleNamespace

import ida_kernwin
import ida_idaapi

import gepetto.config
import gepetto.ida.handlers
from gepetto.ida.status_panel.panel_interface import LogCategory, LogLevel
from gepetto.ida.status_panel.status_panel_factory import get_status_panel
from gepetto.ida.tools.tools import TOOLS
import gepetto.ida.tools as ida_tools

_ = gepetto.config._
STATUS_PANEL = get_status_panel()
CLI: ida_kernwin.cli_t = None
MESSAGES: list[dict] = [
    {
        "role": "system",
        "content":
            f"You are a helpful assistant embedded in IDA Pro. Your role is to facilitate "
            f"reverse-engineering and answer programming questions.\n"
            f"Your response MUST ALWAYS be in the following locale: {gepetto.config.get_localization_locale()}\n"
            f"If you format your response, you MUST ALWAYS use basic Markdown; but formatting is not required.\n"
            f"Bullets start at column 0 with - or * ; do not indent lists, use HTML tags, or pre blocks.\n"
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

_REASONING_KEYS = ("reasoning", "thinking", "thought", "internal_monologue")
_REASONING_TYPES = {"reasoning", "thinking", "thought"}


def _collect_reasoning_text(value, collector, depth=0):
    if depth > 5 or value is None:
        return
    if isinstance(value, str):
        if value.strip():
            collector.append(value)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_reasoning_text(item, collector, depth + 1)
        return
    if isinstance(value, dict):
        value_type = value.get("type")
        if value_type in _REASONING_TYPES:
            candidate = value.get("text") or value.get("content")
            _collect_reasoning_text(candidate, collector, depth + 1)
            return
        for key in _REASONING_KEYS:
            if key in value:
                _collect_reasoning_text(value[key], collector, depth + 1)
        if "text" in value:
            _collect_reasoning_text(value["text"], collector, depth + 1)
        if "content" in value:
            _collect_reasoning_text(value["content"], collector, depth + 1)
        return

    for attr in ("text", "content"):
        if hasattr(value, attr):
            _collect_reasoning_text(getattr(value, attr), collector, depth + 1)
    remaining = str(value).strip()
    if remaining:
        collector.append(remaining)


def _append_reasoning_from_delta(delta) -> None:
    if delta is None:
        return
    containers = []
    if isinstance(delta, dict):
        containers.extend(delta.get(key) for key in _REASONING_KEYS if delta.get(key))
        content = delta.get("content")
    elif isinstance(delta, str):
        return
    else:
        for key in _REASONING_KEYS:
            value = getattr(delta, key, None)
            if value:
                containers.append(value)
        content = getattr(delta, "content", None)

    if isinstance(content, (list, tuple)):
        for item in content:
            item_type = None
            item_text = None
            if isinstance(item, dict):
                item_type = item.get("type")
                item_text = item.get("text") or item.get("content")
            else:
                item_type = getattr(item, "type", None)
                item_text = getattr(item, "text", None) or getattr(item, "content", None)
            if item_type in _REASONING_TYPES:
                containers.append(item_text)

    texts: list[str] = []
    for container in containers:
        _collect_reasoning_text(container, texts)

    for chunk in texts:
        STATUS_PANEL.append_reasoning(chunk)


class GepettoCLI(ida_kernwin.cli_t):
    flags = 0
    sname = "Gepetto"
    lname  = "Gepetto - " + _("LLM chat")
    hint = "Gepetto"

    def OnExecuteLine(self, line):
        if not line.strip():  # Don't do anything for empty sends.
            return True

        MESSAGES.append({"role": "user", "content": line})
        if gepetto.config.auto_show_status_panel_enabled():
            STATUS_PANEL.ensure_shown()
        STATUS_PANEL.set_stop_callback(getattr(gepetto.config.model, "cancel_current_request", None))
        STATUS_PANEL.log_user(line)
        STATUS_PANEL.start_stream()
        STATUS_PANEL.log_request_started()

        stream_retry_attempted = False

        def handle_response(response):
            if hasattr(response, "tool_calls") and response.tool_calls:
                tool_calls = []
                STATUS_PANEL.finish_stream(response.content or "")
                STATUS_PANEL.finish_reasoning()
                for tc in response.tool_calls:
                    tool_calls.append({
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    })
                    STATUS_PANEL.log(
                        _("→ Model requested tool: {tool_name} ({tool_args}...)").format(
                            tool_name=tc.function.name,
                            tool_args=(tc.function.arguments or "")[:120],
                        ),
                        category=LogCategory.TOOL,
                    )
                MESSAGES.append(
                    {
                        "role": "assistant",
                        "content": response.content or "",
                        "tool_calls": tool_calls,
                    }
                )

                first_tool_name = response.tool_calls[0].function.name
                STATUS_PANEL.set_status(_("Using tool: {tool_name}").format(tool_name=first_tool_name), busy=True)
                for tc in response.tool_calls:
                    if tc.function.name == "get_screen_ea":
                        ida_tools.get_screen_ea.handle_get_screen_ea_tc(tc, MESSAGES)
                    elif tc.function.name == "get_current_function":
                        ida_tools.get_current_function.handle_get_current_function_tc(tc, MESSAGES)
                    elif tc.function.name == "get_ea":
                        ida_tools.get_ea.handle_get_ea_tc(tc, MESSAGES)
                    elif tc.function.name == "decompile_function":
                        ida_tools.decompile_function.handle_decompile_function_tc(tc, MESSAGES)
                    elif tc.function.name == "rename_lvar":
                        ida_tools.rename_lvar.handle_rename_lvar_tc(tc, MESSAGES)
                    elif tc.function.name == "rename_function":
                        ida_tools.rename_function.handle_rename_function_tc(tc, MESSAGES)
                    elif tc.function.name == "set_comment":
                        ida_tools.set_comment.handle_set_comment_tc(tc, MESSAGES)
                    elif tc.function.name == "get_xrefs":
                        ida_tools.get_xrefs.handle_get_xrefs_tc(tc, MESSAGES)
                    elif tc.function.name == "list_imports":
                        ida_tools.list_imports.handle_list_imports_tc(tc, MESSAGES)
                    elif tc.function.name == "list_functions":
                        ida_tools.list_functions.handle_list_functions_tc(tc, MESSAGES)
                    elif tc.function.name == "list_symbols":
                        ida_tools.list_symbols.handle_list_symbols_tc(tc, MESSAGES)
                    elif tc.function.name == "list_strings":
                        ida_tools.search.handle_list_strings_tc(tc, MESSAGES)
                    elif tc.function.name == "search":
                        ida_tools.search.handle_search_tc(tc, MESSAGES)
                    elif tc.function.name == "to_hex":
                        ida_tools.to_hex.handle_to_hex_tc(tc, MESSAGES)
                    elif tc.function.name == "get_disasm":
                        ida_tools.get_disasm.handle_get_disasm_tc(tc, MESSAGES)
                    elif tc.function.name == "get_bytes":
                        ida_tools.get_bytes.handle_get_bytes_tc(tc, MESSAGES)
                    elif tc.function.name == "get_callers":
                        ida_tools.call_graph.handle_get_callers_tc(tc, MESSAGES)
                    elif tc.function.name == "get_callees":
                        ida_tools.call_graph.handle_get_callees_tc(tc, MESSAGES)
                    elif tc.function.name == "declare_c_type":
                        ida_tools.declare_c_type.handle_declare_c_type_tc(tc, MESSAGES)
                    elif tc.function.name == "get_struct":
                        ida_tools.get_struct.handle_get_struct_tc(tc, MESSAGES)
                    elif tc.function.name == "refresh_view":
                        ida_tools.refresh_view.handle_refresh_view_tc(tc, MESSAGES)
                STATUS_PANEL.start_stream()
                start_model_interaction()
            else:
                content = response.content or ""
                MESSAGES.append({"role": "assistant", "content": content})
                STATUS_PANEL.finish_stream(content)
                STATUS_PANEL.finish_reasoning()
                STATUS_PANEL.log(
                    _("✔ Completed turn"),
                    category=LogCategory.SYSTEM,
                    level=LogLevel.SUCCESS,
                )

        def handle_non_streaming_response(response):
            """Handle non-streaming response from the model."""
            if hasattr(response, "error"):
                error_text = str(response.error) if response.error else _("Model request failed.")
                STATUS_PANEL.mark_error(error_text)
                return
            
            # Print the response content to console
            if response.content:
                print(response.content, end="\n\n")
            
            handle_response(response)

        def handle_streaming():
            message = SimpleNamespace(content="", tool_calls=[])
            last_error_message = ""

            def handle_model_error(text: str | None) -> None:
                nonlocal last_error_message, stream_retry_attempted
                error_text = (text or "").strip()
                if not error_text:
                    error_text = _("Model request failed.")
                last_error_message = error_text
                STATUS_PANEL.finish_stream(message.content)
                STATUS_PANEL.finish_reasoning()
                supports_streaming_method = getattr(gepetto.config.model, "supports_streaming", None)
                should_retry_without_stream = (
                    not stream_retry_attempted
                    and callable(supports_streaming_method)
                    and not supports_streaming_method()
                )
                if should_retry_without_stream:
                    stream_retry_attempted = True
                    STATUS_PANEL.log(
                        _("Streaming unavailable for this model; retrying without streaming."),
                        category=LogCategory.SYSTEM,
                    )
                    STATUS_PANEL.set_status(_("Retrying without streaming"), busy=True)
                    STATUS_PANEL.start_stream()
                    start_model_interaction()
                    return
                STATUS_PANEL.mark_error(error_text)

            def on_chunk(delta, finish_reason):
                nonlocal last_error_message
                delta_error = None
                if isinstance(delta, dict):
                    delta_error = delta.get("error")
                elif delta is not None:
                    delta_error = getattr(delta, "error", None)
                if delta_error:
                    handle_model_error(str(delta_error))
                    return
                if isinstance(delta, str):
                    print(delta, end="", flush=True)
                    message.content += delta
                    STATUS_PANEL.append_stream(delta)
                    _append_reasoning_from_delta(delta)
                    return
                if getattr(delta, "content", None):
                    print(delta.content, end="", flush=True)
                    message.content += delta.content
                    STATUS_PANEL.append_stream(delta.content)
                _append_reasoning_from_delta(delta)
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
                    if finish_reason == "error":
                        handle_model_error(last_error_message)
                        return
                    if finish_reason != "tool_calls":
                        print("\n\n")  # Add a blank line after the model's reply for readability.
                    STATUS_PANEL.finish_reasoning()
                    handle_response(message)

            gepetto.config.model.query_model_async(
                MESSAGES,
                on_chunk,
                stream=True,
                additional_model_options={"tools": TOOLS},
            )

        def start_model_interaction():
            supports_streaming = True
            supports_streaming_method = getattr(gepetto.config.model, "supports_streaming", None)
            if callable(supports_streaming_method):
                try:
                    supports_streaming = bool(supports_streaming_method())
                except Exception:
                    supports_streaming = True
            if supports_streaming:
                handle_streaming()
            else:
                gepetto.config.model.query_model_async(
                    MESSAGES,
                    handle_non_streaming_response,
                    stream=False,
                    additional_model_options={"tools": TOOLS},
                )

        print()  # Add a line break before the model's response to improve readability
        start_model_interaction()
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
