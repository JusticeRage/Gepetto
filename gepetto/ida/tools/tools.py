import json
from typing import Any


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
            "name": "get_current_function",
            "description": "Return the current function under the cursor.",
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
            "description": "Convert a decimal integer to a hexadecimal string (returns {\"hex\": \"0x...\"}).",
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
                        "type": "string",
                        "description": "EA (int or hex string) to disassemble.",
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
                        "type": "string",
                        "description": "EA (int or hex string) to read from.",
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
            "name": "decompile_function",
            "description": "Decompile a function by EA or name and return annotated pseudocode (with per-line metadata). Provide either `ea` or `name`.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "string",
                        "description": "EA (int or hex string) inside the target function.",
                    },
                    "name": {
                        "type": "string",
                        "description": "Function name to resolve if no EA is supplied.",
                    },
                },
            },
        },
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
                        "type": "string",
                        "description": "EA (int or hex string) inside the target function.",
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
                "required": ["new_name", "old_name"],
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
                        "type": "string",
                        "description": "EA (int or hex string) inside the target function.",
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
                "required": ["new_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_comment",
            "description": "Set a non-repeatable comment at a given EA. Supports multiline input.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "string",
                        "description": "EA (int or hex string) where the comment should be applied.",
                    },
                    "comment": {
                        "type": "string",
                        "description": "Comment text to store at the address.",
                    },
                },
                "required": ["ea", "comment"],
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
                    "with practical filters (kind/only_calls/exclude_flow) and "
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
                    "kind": {
                        "type": "string",
                        "description": "Limit results to code, data, or both kinds of xrefs.",
                        "enum": ["code", "data", "both"],
                        "default": "both"
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
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_imports",
            "description": "Enumerate imported functions; supports pagination and module filtering.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 256, "minimum": 1},
                    "offset": {"type": "integer", "default": 0, "minimum": 0},
                    "module_filter": {
                        "type": "string",
                        "description": "Substring to match import module name (case-insensitive).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_functions",
            "description": "Paginated function enumeration with optional thunk filtering.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 256, "minimum": 1},
                    "offset": {"type": "integer", "default": 0, "minimum": 0},
                    "include_thunks": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        },
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
                        "description": "Optional segment names to restrict enumeration (e.g., ['.text', '.rdata']).",
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
                    "ea": {
                        "type": "string",
                        "description": "EA (int or hex string) inside the target function.",
                    },
                    "name": {"type": "string", "description": "Function name to resolve."},
                    "include_thunks": {"type": "boolean", "default": True, "description": "Treat thunks as their targets."}
                },
                            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "declare_c_type",
            "description": "Parse and declare C types into the local type library.",
            "parameters": {
                "type": "object",
                "properties": {
                    "c_declaration": {
                        "type": "string",
                        "description": "C declaration(s) to add to the Local Types view.",
                    },
                },
                "required": ["c_declaration"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_struct",
            "description": "Return structure fields and metadata by name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Structure name to query from the Local Types view.",
                    },
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "refresh_view",
            "description": "Force IDA to repaint views after renames or patches.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
]

def tool_result_payload(data: Any) -> dict[str, Any]:
    """Wrap successful tool results in a standard payload structure."""

    return {"type": "result", "data": data}


def tool_error_payload(message: str, **context: Any) -> dict[str, Any]:
    """Create an error payload with an optional context dictionary."""

    error: dict[str, Any] = {"message": message}
    if context:
        error["context"] = context
    return {"type": "error", "error": error}


def add_result_to_messages(messages, tc, result):
    tc_id = getattr(tc, "id", None) or tc.get("id")
    fn_name = getattr(getattr(tc, "function", None), "name", None) \
              or (tc.get("function") or {}).get("name", "get_xrefs")
    messages.append(
        {
            "role": "tool",
            "tool_call_id": tc_id,
            "name": fn_name,
            "content": json.dumps(result, ensure_ascii=False),
        }
    )
