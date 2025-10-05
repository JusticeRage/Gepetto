import json
from typing import Optional, Dict

import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name

from gepetto.ida.tools.function_utils import parse_ea, resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_get_function_code_tc(tc, messages):
    # Parse args (ea or name). Be forgiving if arguments are missing or malformed.
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception as e:
        args = {}

    ea = args.get("ea", None)
    if ea is not None:
        ea = parse_ea(ea)
    name = args.get("name", None)

    try:
        data = get_function_code(ea=ea, name=name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            ea=ea,
            name=name,
        )

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

def _decompile_func(ea) -> str:
    """
    Decompile with Hex-Rays on the UI thread and return pseudocode.
    Raises ValueError if decompilation fails.
    """
    res: dict[str, str | None] = {"text": None, "err": None}

    def _do():
        try:
            decompiled = ida_hexrays.decompile(ea)
            if not decompiled:
                res["err"] = "Decompilation failed."
                return 0
            res["text"] = str(decompiled)
            return 1
        except Exception as e:
            res["err"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

    if res["text"] is None:
        raise ValueError(res["err"] or "Unknown decompilation error.")
    return res["text"]

# -----------------------------------------------------------------------------

def get_function_code(ea: Optional[int] = None,
                      name: Optional[str] = None) -> Dict:
    """Return Hex-Rays pseudocode for the target function."""

    f = resolve_func(ea=ea, name=name)
    func_name = name or get_func_name(f)
    target_ea = ea or resolve_ea(func_name)
    pseudocode = _decompile_func(target_ea)

    return {
        "ea": int(f.start_ea),
        "end_ea": int(f.end_ea),
        "func_name": func_name,
        "pseudocode": pseudocode,
    }
