import json

import ida_kernwin
import ida_funcs
import ida_name
import idautils

from gepetto.ida.tools.tools import add_result_to_messages



def handle_list_symbols_tc(tc, messages):
    """Handle a tool call to list symbols."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    prefix = args.get("prefix") or ""
    include_globals = bool(args.get("include_globals", False))

    try:
        result = list_symbols(prefix=prefix, include_globals=include_globals)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)


# -----------------------------------------------------------------------------


def list_symbols(prefix: str = "", include_globals: bool = False) -> dict:
    """Return names and EAs for functions and (optionally) global symbols."""
    out = {"ok": False, "symbols": [], "error": None}

    def _do():
        try:
            results = []
            pref = prefix or ""
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea) or ida_name.get_ea_name(ea) or ""
                if pref and not name.startswith(pref):
                    continue
                results.append({"name": name, "ea": int(ea), "type": "function"})

            if include_globals:
                for ea, name in idautils.Names():
                    if ida_funcs.get_func(ea):
                        continue
                    if pref and not name.startswith(pref):
                        continue
                    results.append({"name": name, "ea": int(ea), "type": "global"})

            out["symbols"] = results
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out
