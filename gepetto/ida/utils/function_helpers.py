import idaapi
import ida_funcs
import ida_kernwin
import ida_name


def parse_ea(ea_val):
    """Accept ints or hex-like strings ('0x22A38', '22A38', '22A38h').
    Return int EA or raise ValueError."""
    if ea_val is None:
        raise ValueError("No EA provided")
    if isinstance(ea_val, int):
        return ea_val
    if isinstance(ea_val, str):
        s = ea_val.strip()
        if s[-1:] in ("h", "H"):
            s = "0x" + s[:-1]
        return int(s, 0)
    raise ValueError(f"Unsupported EA type: {type(ea_val).__name__}")


def resolve_ea(name) -> int:
    """Resolve a function name to its effective address."""
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


def resolve_func(ea=None, name=None):
    """Resolve a function by EA or name on the UI thread."""
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


def get_func_name(f) -> str:
    """Fetch a function's name on the main thread with a read lock."""
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
