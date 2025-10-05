import json
from typing import Optional

import ida_hexrays
import ida_kernwin

from gepetto.ida.tools.function_utils import parse_ea, resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)



def handle_rename_lvar_tc(tc, messages):
    """Handle a tool call to rename a local variable."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        ea = parse_ea(ea)
    func_name = args.get("func_name")
    old_name = args.get("old_name")
    new_name = args.get("new_name")

    try:
        data = rename_lvar(ea=ea, func_name=func_name, old_name=old_name, new_name=new_name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            ea=ea,
            func_name=func_name,
            old_name=old_name,
            new_name=new_name,
        )

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------

def rename_lvar(
    ea: Optional[int] = None,
    func_name: Optional[str] = None,
    old_name: Optional[str] = None,
    new_name: Optional[str] = None,
) -> dict:
    """Rename a local variable in a function."""
    if not old_name or not new_name:
        raise ValueError("old_name and new_name are required")

    f = resolve_func(ea=ea, name=func_name)
    func_name = func_name or get_func_name(f)
    if ea is None:
        ea = resolve_ea(func_name)

    result = {"ea": int(f.start_ea), "func_name": func_name, "old_name": old_name, "new_name": new_name}
    error: dict[str, str | None] = {"message": None}

    def _do():
        try:
            if not ida_hexrays.rename_lvar(ea, old_name, new_name):
                error["message"] = f"Failed to rename lvar {old_name!r}"
                return 0
            return 1
        except Exception as e:
            error["message"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)

    if error["message"]:
        raise RuntimeError(error["message"])
    return result
