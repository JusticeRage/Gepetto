import json
from typing import Optional

import ida_name
import ida_kernwin

from gepetto.ida.tools.function_utils import parse_ea, resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_rename_function_tc(tc, messages):
    """Handle a tool call to rename a function."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        ea = parse_ea(ea)
    name = args.get("name")
    new_name = args.get("new_name")

    try:
        data = rename_function(ea=ea, name=name, new_name=new_name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea, name=name, new_name=new_name)
    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


def rename_function(
    ea: Optional[int] = None,
    name: Optional[str] = None,
    new_name: Optional[str] = None,
) -> dict:
    """Rename a function by EA or name."""
    if not new_name:
        raise ValueError("new_name is required")

    f = resolve_func(ea=ea, name=name)
    old_name = name or get_func_name(f)
    ea = int(f.start_ea)

    error: dict[str, Optional[str]] = {"message": None}

    def _do():
        try:
            if not ida_name.set_name(ea, new_name):
                error["message"] = f"Failed to rename function {old_name!r}"
                return 0
            return 1
        except Exception as e:
            error["message"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)

    if error["message"]:
        raise RuntimeError(error["message"])

    return {"ea": ea, "old_name": old_name, "new_name": new_name}
