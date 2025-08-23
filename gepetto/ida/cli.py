import functools
import json

import ida_kernwin
import ida_idaapi
import idaapi

import gepetto.config
import gepetto.ida.handlers

_ = gepetto.config._
CLI: ida_kernwin.cli_t = None
MESSAGES: list[dict] = [
    {
        "role": "system",
        "content": _(
            "You are a helpful assistant embedded in IDA Pro. Your role is to facilitate "
            "reverse-engineering and answer programming questions."
        ),
    }
]  # Keep a history of the conversation to simulate LLM memory.

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_screen_ea",
            "description": "Return the current effective address (EA).",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    }
]


def get_screen_ea() -> str:
    """Return the current effective address as a hexadecimal string."""
    ea = idaapi.get_screen_ea()
    return hex(ea)

class GepettoCLI(ida_kernwin.cli_t):
    flags = 0
    sname = "Gepetto"
    lname  = "Gepetto - " + _("LLM chat")
    hint = "Gepetto"

    def OnExecuteLine(self, line):
        MESSAGES.append({"role": "user", "content": line})

        def handle_response(response):
            if hasattr(response, "tool_calls") and response.tool_calls:
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
                    if tc.function.name == "get_screen_ea":
                        # The tool takes no arguments, but parse for forward compatibility.
                        _ = json.loads(tc.function.arguments or "{}")
                        result = get_screen_ea()
                        MESSAGES.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "content": result,
                            }
                        )
                gepetto.config.model.query_model_async(
                    MESSAGES,
                    handle_response,
                    stream=False,
                    additional_model_options={"tools": TOOLS},
                )
            else:
                if response.content:
                    print(response.content)
                MESSAGES.append({"role": "assistant", "content": response.content or ""})

        gepetto.config.model.query_model_async(
            MESSAGES,
            handle_response,
            stream=False,
            additional_model_options={"tools": TOOLS},
        )
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
