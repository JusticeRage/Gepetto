import json
from typing import Optional, Dict

import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name


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

def _parse_ea(ea_val):
    """
    Accept ints or hex-like strings ('0x22A38', '22A38', '22A38h').
    Return int EA or raise ValueError.
    """
    if ea_val is None:
        raise ValueError("No EA provided")
    if isinstance(ea_val, int):
        return ea_val
    if isinstance(ea_val, str):
        s = ea_val.strip()
        # accept trailing 'h'
        if s[-1:] in ("h", "H"):
            s = "0x" + s[:-1]
        # int(..., 0) handles 0x, 0o, 0b, or decimal
        return int(s, 0)
    raise ValueError(f"Unsupported EA type: {type(ea_val).__name__}")

# -----------------------------------------------------------------------------

def _resolve_ea(name) -> int:
    """
    Resolves a function name to the corresponding effective address
    """
    out = {"ea": None, "err": None}

    def _do():
        try:
            ne = ida_name.get_name_ea(idaapi.BADADDR, name)
            if ne == idaapi.BADADDR:
                out["err"] = f"Name not found: {name!r}"
                return 0
            out["ea"] = int(ne)
            return 1
        except Exception as e:
            out["err"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)

    if out["ea"] is None:
        raise ValueError(out["err"] or "Failed to resolve EA")

    return out["ea"]

# -----------------------------------------------------------------------------

def _resolve_func(ea=None, name=None):
    """
    Runs on UI thread.
    If 'name' is given, resolve by name. Else use EA first,
    then ask IDA for the function containing that EA.
    """
    out = {"func": None, "err": None}

    def _do():
        try:
            import idaapi, ida_funcs, ida_name
            if name:
                name_ea = ida_name.get_name_ea(idaapi.BADADDR, name)
                if name_ea == idaapi.BADADDR:
                    out["err"] = f"Name not found: {name!r}"
                    return 0
                f = ida_funcs.get_func(name_ea)
                if not f:
                    out["err"] = f"Symbol {name!r} not inside a function."
                    return 0
                out["func"] = f
                return 1
            # EA path
            f = ida_funcs.get_func(ea)
            if not f:
                out["err"] = f"EA 0x{ea:X} is not inside a function."
                return 0
            out["func"] = f
            return 1
        except Exception as e:
            out["err"] = str(e); return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    if not out["func"]:
        raise ValueError(out["err"] or "Failed to resolve function")
    return out["func"]

# -----------------------------------------------------------------------------

def _get_func_name(f) -> str:
    """Fetch function name on the main thread with a read lock."""
    out = {"name": ""}
    def _do():
        out["name"] = (
                ida_funcs.get_func_name(f.start_ea)
                or ida_name.get_ea_name(f.start_ea)
                or ""
        )
        return 1
    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out["name"]

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
