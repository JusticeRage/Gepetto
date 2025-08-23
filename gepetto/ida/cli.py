import functools
import json

import ida_kernwin
import ida_idaapi
import ida_hexrays
import idaapi

import gepetto.config
import gepetto.ida.handlers
from gepetto.ida.comment_handler import get_commentable_lines

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
            "name": "add_comment",
            "description": "Add a comment to a given line in the currently decompiled function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "line_number": {
                        "type": "integer",
                        "description": "Line number in the current function to comment.",
                    },
                    "comment": {
                        "type": "string",
                        "description": "Text of the comment to set.",
                    },
                },
                "required": ["line_number", "comment"],
            },
        },
    }
]


def add_comment(line_number: int, comment: str) -> str:
    """Add a comment to the specified line of the current decompiled function."""
    try:
        cfunc = ida_hexrays.decompile(idaapi.get_screen_ea())
    except Exception:
        return "No function available for commenting."

    lines = get_commentable_lines(cfunc)
    if line_number < 0 or line_number >= len(lines):
        return f"Line {line_number} out of range."

    comment_address = lines[line_number][2]
    comment_placement = lines[line_number][3]
    if comment_address is None:
        return f"Line {line_number} cannot be commented."

    target = idaapi.treeloc_t()
    target.ea = comment_address
    target.itp = comment_placement
    cfunc.set_user_cmt(target, comment)
    cfunc.save_user_cmts()
    cfunc.del_orphan_cmts()

    return f"Comment added to line {line_number}."

class GepettoCLI(ida_kernwin.cli_t):
    flags = 0
    sname = "Gepetto"
    lname  = "Gepetto - " + _("LLM chat")
    hint = "Gepetto"

    def OnExecuteLine(self, line):
        MESSAGES.append({"role": "user", "content": line})

        def handle_response(message):
            if hasattr(message, "tool_calls") and message.tool_calls:
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in message.tool_calls
                ]
                MESSAGES.append(
                    {
                        "role": "assistant",
                        "content": message.content or "",
                        "tool_calls": tool_calls,
                    }
                )
                for tc in message.tool_calls:
                    if tc.function.name == "add_comment":
                        args = json.loads(tc.function.arguments)
                        result = add_comment(args["line_number"], args["comment"])
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
                if message.content:
                    print(message.content)
                MESSAGES.append({"role": "assistant", "content": message.content or ""})

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
