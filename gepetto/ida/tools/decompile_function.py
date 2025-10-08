import json
from typing import Any, Dict, List, Optional

import ida_hexrays
import ida_lines
import idaapi

import gepetto.config
from gepetto.ida.utils.thread_helpers import *
from gepetto.ida.tools.function_utils import (
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
        data = decompile_function(address=address, ea=ea_arg, name=name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            address=address,
            ea=ea_arg,
            name=name,
        )

    add_result_to_messages(messages, tc, payload)


def decompile_function(
    address: Optional[Any] = None,
    ea: Optional[Any] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decompile the function identified by ``address``/``ea``/``name`` and return annotated pseudocode.
    """

    target_ea: Optional[int] = None
    if address is not None:
        target_ea = parse_ea(address)
    elif ea is not None:
        target_ea = parse_ea(ea)

    function = resolve_func(ea=target_ea, name=name)
    func_name = name or get_func_name(function)
    if target_ea is None:
        target_ea = resolve_ea(func_name)

    def _produce() -> Dict[str, Any]:
        cfunc = decompile_func(target_ea)
        entry_ea = getattr(cfunc, "entry_ea", int(function.start_ea))
        pseudocode_lines = cfunc.get_pseudocode()

        lines: List[Dict[str, Any]] = []
        text_lines: List[str] = []

        for idx, line in enumerate(pseudocode_lines):
            try:
                stripped = ida_lines.tag_remove(line.line)
            except Exception:
                stripped = str(line.line)

            line_ea: Optional[int] = None
            item = ida_hexrays.ctree_item_t()
            try:
                if cfunc.get_line_item(line.line, 0, False, None, item, None):
                    candidate = getattr(item, "ea", idaapi.BADADDR)
                    if isinstance(candidate, int) and candidate != idaapi.BADADDR:
                        line_ea = int(candidate)
                    else:
                        parts = item.dstr().split(": ")
                        if len(parts) >= 2:
                            line_ea = int(parts[0], 16)
            except Exception:
                line_ea = None

            if line_ea is None and idx == 0 and isinstance(entry_ea, int):
                line_ea = int(entry_ea)

            lines.append(
                {
                    "index": idx,
                    "text": stripped,
                    "ea": line_ea,
                }
            )
            text_lines.append(stripped)

        return {
            "pseudocode": "\n".join(text_lines),
            "lines": lines,
        }

    payload = run_on_main_thread(_produce, write=False)
    if not isinstance(payload, dict):
        raise RuntimeError("Failed to gather pseudocode.")

    return {
        "ea": int(function.start_ea),
        "end_ea": int(function.end_ea),
        "func_name": func_name,
        **payload,
    }
