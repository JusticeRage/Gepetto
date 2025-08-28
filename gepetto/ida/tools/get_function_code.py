import json
from typing import Optional, Dict

import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name

from .function_utils import (
    parse_ea as _parse_ea,
    resolve_ea as _resolve_ea,
    resolve_func as _resolve_func,
    get_func_name as _get_func_name,
)


def handle_get_function_code_tc(tc, messages):
    # Parse args (ea or name). Be forgiving if arguments are missing or malformed.
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception as e:
        args = {}

    ea = args.get("ea", None)
    if ea is not None:
        ea = _parse_ea(ea)
    name = args.get("name", None)

    try:
        result = get_function_code(ea=ea, name=name)
    except Exception as ex:
        result = {
            "ok": False,
            "error": str(ex),
            "ea": None,
            "end_ea": None,
            "func_name": None,
            "pseudocode": None,
        }

    # Tool messages must be strings; serialize the result dict.
    messages.append(
        {
            "role": "tool",
            "tool_call_id": tc.id,
            "content": json.dumps(result, ensure_ascii=False),
        }
    )

# -----------------------------------------------------------------------------

def _decompile_func(ea) -> str:
    """
    Decompile with Hex-Rays on the UI thread and return pseudocode.
    Raises ValueError if decompilation fails.
    """
    res = {"ok": False, "text": None, "err": None}

    def _do():
        try:
            decompiled = ida_hexrays.decompile(ea)
            if not decompiled:
                res["ok"] = False
                res["err"] = "Decompilation failed."
                return 0
            res["text"] = str(decompiled)
            res["ok"] = True
            return 1
        except Exception as e:
            res["err"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

    if not res["ok"]:
        raise ValueError(res["err"] or "Unknown decompilation error.")
    return res["text"]

# -----------------------------------------------------------------------------

def get_function_code(ea: Optional[int] = None,
                      name: Optional[str] = None) -> Dict:
    """
    Return Hex-Rays pseudocode for the target function.

    Parameters:
        ea (int, optional): Effective address inside the function.
        name (str, optional): Function name.

    Returns:
        dict: {
          "ok": bool,
          "error": str | None,
          "ea": int | None,        # start EA
          "end_ea": int | None,    # end EA (IDA-exclusive)
          "func_name": str | None,
          "pseudocode": str | None
        }
    """
    result = {
        "ok": False,
        "error": None,
        "ea": None,
        "end_ea": None,
        "func_name": None,
        "pseudocode": None,
    }

    try:
        f = _resolve_func(ea=ea, name=name)
        func_name = name or _get_func_name(f)
        if not ea:
            ea = _resolve_ea(func_name)
        pseudocode = _decompile_func(ea)

        result.update(
            ok=True,
            ea=int(f.start_ea),
            end_ea=int(f.end_ea),
            func_name=func_name,
            pseudocode=pseudocode,
        )
    except Exception as e:
        result["error"] = str(e)

    return result
