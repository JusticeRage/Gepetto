import ida_kernwin

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
            "description": "Return cross-references to or from an address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address (EA) to inspect, in decimal or hex.",
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["to", "from"],
                        "description": "Direction of cross-references: 'to' for incoming, 'from' for outgoing.",
                    },
                },
            },
        },
    },
]
