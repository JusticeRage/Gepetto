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
        "function": {
            "name": "get_screen_ea",
            "description": "Return the current effective address (EA).",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
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
            },
        },
    },
    {
        "type": "function",
        "function": {
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
            },
        },
    },
    {
        "type": "function",
        "function": {
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
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_bytes",
            "description": "Return raw bytes for an effective address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address to read from.",
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of bytes to retrieve starting at the address.",
                        "default": 32,
                    },
                },
                "required": ["ea"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_code",
            "description": "Return Hex-Rays pseudocode for a function, resolved by EA or by name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address (EA) inside the target function, in either decimal or hex."
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the function to resolve."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rename_lvar",
            "description": "Rename a local variable within a function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address (EA) inside the target function, in either decimal or hex.",
                    },
                    "func_name": {
                        "type": "string",
                        "description": "Name of the function if EA is not provided.",
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
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_function",
            "description": "Rename a function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address (EA) inside the target function, in either decimal or hex.",
                    },
                    "name": {
                        "type": "string",
                        "description": "Existing function name if EA is not provided.",
                    },
                    "new_name": {
                        "type": "string",
                        "description": "Desired new name for the function.",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
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
                        "enum": ["ea", "function", "name"],
                        "default": "ea"
                    },
                    "subject": {
                        "type": "string",
                        "description": (
                            "Subject to inspect. If scope=='ea' or 'function', this may be an EA "
                            "as decimal or hex string ('0x401000', '401000h'). "
                            "If scope=='name', this must be a symbol name."
                        )
                    },
                    "direction": {
                        "type": "string",
                        "description": "Which direction of xrefs to return.",
                        "enum": ["to", "from", "both"],
                        "default": "both"
                    },
                    "only_code": {
                        "type": "boolean",
                        "description": "Limit to code xrefs only.",
                        "default": False
                    },
                    "only_data": {
                        "type": "boolean",
                        "description": "Limit to data xrefs only.",
                        "default": False
                    },
                    "only_calls": {
                        "type": "boolean",
                        "description": "For code xrefs, keep only call sites.",
                        "default": False
                    },
                    "exclude_flow": {
                        "type": "boolean",
                        "description": "Exclude simple flow xrefs (falls-through/jumps).",
                        "default": False
                    },
                    "collapse_by": {
                        "type": "string",
                        "description": (
                            "Dedup granularity: 'site' (no dedup), 'pair' (from_ea→to_ea), "
                            "'from_func' (collapse by caller function), or 'to_func' (callee function)."
                        ),
                        "enum": ["site", "pair", "from_func", "to_func"],
                        "default": "site"
                    },
                    "enrich_names": {
                        "type": "boolean",
                        "description": "Add best-effort names for endpoints (functions/data).",
                        "default": True
                    },

                    # Back-compat shims (optional): callers may still pass these
                    "ea": {
                        "type": "string",
                        "description": "Deprecated: EA as decimal/hex string if not using 'subject'."
                    },
                    "name": {
                        "type": "string",
                        "description": "Deprecated: symbol name if not using 'subject'."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_symbols",
            "description": (
                "Return names and EAs for functions, optionally including globals. "
                "Supports prefix filtering."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "prefix": {
                        "type": "string",
                        "description": "Only include symbols whose name starts with this prefix.",
                    },
                    "include_globals": {
                        "type": "boolean",
                        "description": "Include global (non-function) symbols.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search the binary for specific text strings or hex byte patterns. Returns the addresses (EAs) where matches were found. For enumerating all strings, use the `list_strings` function instead.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to search for (ASCII/Unicode, case-insensitive by default)."
                    },
                    "hex": {
                        "type": "string",
                        "description": "Hex byte pattern like '90 90 ?? FF'."
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "Whether the text search should be case-sensitive.",
                        "default": False
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_strings",
            "description": "Enumerate discovered strings with pagination and filters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "default": 200, "minimum": 1 },
                    "offset": { "type": "integer", "default": 0, "minimum": 0 },
                    "min_len": { "type": "integer", "default": 4, "minimum": 1 },
                    "encodings": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["ascii","utf8","utf16","utf32"] }
                    },
                    "segments": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "include_xrefs": { "type": "boolean", "default": False },
                    "include_text": { "type": "boolean", "default": True },
                    "max_text_bytes": { "type": "integer", "default": 256, "minimum": 1 },
                    "return_addresses_only": { "type": "boolean", "default": False },
                    "sort_by": {
                        "type": "string",
                        "enum": ["ea","len","segment"],
                        "default": "ea"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_callers",
            "description": "Return the unique caller functions of a target function (by EA or name).",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {"type": "integer", "description": "EA inside the target function."},
                    "name": {"type": "string", "description": "Function name to resolve."},
                    "include_thunks": {"type": "boolean", "default": True, "description": "Treat thunks as their targets."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_callees",
            "description": "Return the unique callee functions reached from the target function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {"type": "integer"},
                    "name": {"type": "string"},
                    "only_direct": {"type": "boolean", "default": True, "description": "Direct calls only (not xrefs through data)."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "refresh_view",
            "description": "Refresh the current IDA disassembly view to show recent changes.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
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
