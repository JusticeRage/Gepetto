import json

import ida_hexrays  # type: ignore

from gepetto.ida.utils.function_helpers import parse_ea, resolve_ea, resolve_func, get_func_name
from gepetto.ida.utils.thread_helpers import ida_write
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
    ea: int | None = None,
    func_name: str | None = None,
    old_name: str | None = None,
    new_name: str | None = None,
) -> dict:
    """Rename a local variable in a function."""
    if not old_name or not new_name:
        raise ValueError("old_name and new_name are required")

    f = resolve_func(ea=ea, name=func_name)
    func_name = func_name or get_func_name(f)
    if ea is None:
        ea = resolve_ea(func_name)

    result = {"ea": int(f.start_ea), "func_name": func_name, "old_name": old_name, "new_name": new_name}
    _apply_lvar_rename(ea, old_name, new_name)
    return result


@ida_write
def _apply_lvar_rename(ea: int, old_name: str, new_name: str) -> None:
    if not ida_hexrays.rename_lvar(ea, old_name, new_name):
        raise RuntimeError(f"Failed to rename lvar {old_name!r}")
