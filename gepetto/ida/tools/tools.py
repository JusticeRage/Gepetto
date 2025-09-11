import json

import ida_kernwin


def _get(obj, key, default=None):
    """Safely get a value from either a dict or an object.

    Handles both mapping-style (dict) and attribute-style (SimpleNamespace)
    access so tool call payloads can be passed around uniformly.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

TOOLS = [
    {
        "type": "function",
        "name": "get_screen_ea",
        "description": "Return the current effective address (EA).",
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_ea",
        "description": "Return EA for a symbol name.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Symbol or function name.",
                },
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "to_hex",
        "description": "Convert a decimal integer to a hexadecimal string.",
        "parameters": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "integer",
                    "description": "Decimal integer to convert.",
                },
            },
            "required": ["value"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_disasm",
        "description": "Return disassembly for an effective address.",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {
                    "type": "integer",
                    "description": "Effective address to disassemble.",
                },
            },
            "required": ["ea"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_bytes",
        "description": "Return raw bytes for an effective address.",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {
                    "type": "integer",
                    "description": "Effective address to read from.",
                }
            },
            "required": ["ea"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_function_code",
        "description": "Return Hex-Rays pseudocode for a function.",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {
                    "type": "integer",
                    "description": "Effective address (EA) inside the target function, in either decimal or hex."
                },
            },
            "required": ["ea"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "rename_lvar",
        "description": "Rename a local variable within a function.",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {
                    "type": "integer",
                    "description": "Effective address (EA) inside the target function, in either decimal or hex.",
                },
                "old_name": {
                    "type": "string",
                    "description": "Current local variable name to be changed.",
                },
                "new_name": {
                    "type": "string",
                    "description": "Desired new name for the local variable.",
                },
            },
            "required": ["ea", "old_name", "new_name"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "rename_function",
        "description": "Rename a function.",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {
                    "type": "integer",
                    "description": "Effective address (EA) inside the target function, in either decimal or hex.",
                },
                "new_name": {
                    "type": "string",
                    "description": "Desired new name for the function.",
                },
            },
            "required": ["ea", "new_name"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_xrefs",
        "description": (
            "Return cross-references (code/data) for an address, a whole function, "
            "or a named symbol. Supports incoming, outgoing, or both directions, "
            "with practical filters (only_code/only_calls/exclude_flow) and "
            "deduping (collapse_by)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Scope of the query: single EA, the whole function, or a name.",
                    "enum": ["ea", "function", "name"]
                },
                "subject": {
                    "type": "string",
                    "description": (
                        "Subject to inspect. If scope=='ea' or 'function', this may be an EA "
                        "as decimal or hex string ('0x401000', '401000h'). "
                        "If scope=='name', this must be a symbol name."
                    )
                }
            },
            "required": ["scope", "subject"],
            "additionalProperties": False
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "list_symbols",
        "description": (
            "Return names and EAs for functions, optionally including globals. "
            "Supports prefix filtering."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "search",
        "description": "Search the binary for specific text strings or hex byte patterns. Returns the addresses (EAs) where matches were found. For enumerating all strings, use the `list_strings` function instead.",
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to search for (ASCII/Unicode, case-insensitive by default)."
                }
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "list_strings",
        "description": "Enumerate discovered strings with pagination and filters.",
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_callers",
        "description": "Return the unique caller functions of a target function (by EA or name).",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {"type": "integer", "description": "EA inside the target function."}
            },
            "required": ["ea"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "get_callees",
        "description": "Return the unique callee functions reached from the target function.",
        "parameters": {
            "type": "object",
            "properties": {
                "ea": {"type": "integer"}
            },
            "required": ["ea"],
            "additionalProperties": False,
        },
        "strict": False,
    },
    {
        "type": "function",
        "name": "refresh_view",
        "description": "Refresh the current IDA disassembly view to show recent changes.",
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "strict": False,
    },
]

def add_result_to_messages(messages, tc, result):
    # Support both SimpleNamespace tool calls (streaming) and dicts
    tc_id = _get(tc, "id")
    fn = _get(tc, "function", {}) or {}
    fn_name = _get(fn, "name", "get_xrefs")
    messages.append(
        {
            "role": "tool",
            "tool_call_id": tc_id,
            "name": fn_name,
            "content": json.dumps(result, ensure_ascii=False),
        }
    )
