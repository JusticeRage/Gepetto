import json

import ida_name
import idaapi

from gepetto.ida.utils.function_helpers import parse_ea, resolve_ea
from gepetto.ida.utils.thread_helpers import ida_write
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_rename_global_tc(tc, messages):
    """Handle a tool call to rename a global (data) symbol."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        ea = parse_ea(ea)

    old_name = args.get("old_name")
    new_name = args.get("new_name")
    force = args.get("force", False)

    try:
        data = rename_global(ea=ea, old_name=old_name, new_name=new_name, force=force)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea, old_name=old_name, new_name=new_name, force=force)

    add_result_to_messages(messages, tc, payload)


def rename_global(*, ea: int | None = None, old_name: str | None = None, new_name: str | None = None, force: bool = False) -> dict:
    if not new_name or not isinstance(new_name, str) or not new_name.strip():
        raise ValueError("new_name is required")
    new_name = new_name.strip()

    if ea is None:
        if not old_name or not isinstance(old_name, str) or not old_name.strip():
            raise ValueError("Provide either ea or old_name")
        ea = resolve_ea(old_name.strip())

    if ea == idaapi.BADADDR:
        raise ValueError("Could not resolve address")

    _apply_global_rename(ea, new_name, force=bool(force))
    return {"ea": int(ea), "new_name": new_name, "changed": True}



@ida_write
def _apply_global_rename(ea: int, new_name: str, *, force: bool) -> None:
    # Guardrails: make sure the data to rename is a symbol
    f = idaapi.get_func(ea)
    if f is not None and f.start_ea != idaapi.BADADDR:
        raise ValueError("EA is inside a function; use the function-rename tool instead")

    if idaapi.is_code(idaapi.get_flags(ea)):
        raise ValueError("EA appears to be code; refusing to rename as global data")

    flags = ida_name.SN_FORCE if force else ida_name.SN_CHECK
    if not ida_name.set_name(ea, new_name, flags):
        raise RuntimeError(
            f"Failed to rename global at 0x{ea:X} to {new_name!r} "
            f"(invalid name or collision; try force=true if appropriate)"
        )
