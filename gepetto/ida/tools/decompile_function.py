import json
from typing import Any

import ida_funcs
import ida_hexrays
import ida_lines
import idaapi

import gepetto.config
from gepetto.ida.utils.thread_helpers import hexrays_available, run_on_main_thread
from gepetto.ida.utils.function_helpers import (
    get_func_name,
    parse_ea,
    resolve_ea,
    resolve_func,
)
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)

_ = gepetto.config._


def handle_decompile_function_tc(tc, messages):
    """Handle a tool call requesting function decompilation."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    address = args.get("address")
    ea_arg = args.get("ea")
    name = args.get("name")

    try:
        decompiled = decompile_function(address=address, ea=ea_arg, name=name)
        payload = tool_result_payload({"pseudocode": str(decompiled)})
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            address=address,
            ea=ea_arg,
            name=name,
        )

    add_result_to_messages(messages, tc, payload)


def decompile_function(
    address: Any | None = None,
    ea: Any | None = None,
    name: str | None = None,
) -> tuple[dict[str, Any], idaapi.cfuncptr_t]:
    """
    Decompile the function identified by ``address``/``ea``/``name`` and return annotated pseudocode.
    """

    target_ea: int | None = None
    if address is not None:
        target_ea = parse_ea(address)
    elif ea is not None:
        target_ea = parse_ea(ea)

    function = resolve_func(ea=target_ea, name=name)
    func_name = name or get_func_name(function)
    if target_ea is None:
        target_ea = resolve_ea(func_name)

    if not isinstance(target_ea, int) or target_ea == idaapi.BADADDR:
        raise RuntimeError("Invalid function address for decompilation")
    if not hexrays_available():
        raise RuntimeError("Hex-Rays not available: install or enable the decompiler.")

    def _do() -> idaapi.cfuncptr_t:
        func = ida_funcs.get_func(target_ea) if ida_funcs is not None else None
        decompiled = ida_hexrays.decompile(func) if func is not None else ida_hexrays.decompile(target_ea)
        if decompiled is None:
            raise RuntimeError(f"Hex-Rays failed to decompile function at {target_ea:#x}")
        return decompiled

    return run_on_main_thread(_do)
