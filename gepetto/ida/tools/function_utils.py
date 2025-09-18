import idaapi
import ida_funcs
import ida_kernwin
import ida_name
import gepetto.config

_ = gepetto.config._

# Import from our new ida9_utils module
from gepetto.ida.utils.ida9_utils import (
    parse_ea, run_on_main_thread, ea_to_hex, touch_last_ea
)


def resolve_ea(name) -> int:
    """Resolve a function name to its effective address."""
    out = {"ea": None, "err": None}

    def _do():
        try:
            ne = ida_name.get_name_ea(idaapi.BADADDR, name)
            if ne == idaapi.BADADDR:
                out["err"] = _("Name not found: {name!r}").format(name=name)
                return 0
            out["ea"] = int(ne)
            touch_last_ea(ne)  # Track resolved EA
            return 1
        except Exception as e:
            out["err"] = str(e)
            return 0

    run_on_main_thread(_do, write=False)
    if out["ea"] is None:
        raise ValueError(out["err"] or _("Failed to resolve EA"))
    return out["ea"]


def resolve_func(ea=None, name=None):
    """Resolve a function by EA or name on the UI thread."""
    out = {"func": None, "err": None}

    def _do():
        try:
            if name:
                name_ea = ida_name.get_name_ea(idaapi.BADADDR, name)
                if name_ea == idaapi.BADADDR:
                    out["err"] = _("Name not found: {name!r}").format(name=name)
                    return 0
                f = ida_funcs.get_func(name_ea)
                if not f:
                    out["err"] = _("Symbol {name!r} not inside a function.").format(name=name)
                    return 0
                out["func"] = f
                touch_last_ea(name_ea)  # Track resolved EA
                return 1
            f = ida_funcs.get_func(ea)
            if not f:
                out["err"] = _("EA {ea} is not inside a function.").format(ea={ea_to_hex(ea)})
                return 0
            out["func"] = f
            touch_last_ea(ea)  # Track used EA
            return 1
        except Exception as e:
            out["err"] = str(e); return 0

    run_on_main_thread(_do, write=False)
    if not out["func"]:
        raise ValueError(out["err"] or _("Failed to resolve function"))
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

    run_on_main_thread(_do, write=False)
    return out["name"]
