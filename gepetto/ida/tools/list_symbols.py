import json

import ida_kernwin

import ida_funcs
import ida_name
import idautils

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)



def handle_list_symbols_tc(tc, messages):
    """Handle a tool call to list symbols."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    prefix = args.get("prefix") or ""
    include_globals = bool(args.get("include_globals", False))

    try:
        data = list_symbols(prefix=prefix, include_globals=include_globals)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), prefix=prefix, include_globals=include_globals)

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


def list_symbols(prefix: str = "", include_globals: bool = False) -> dict:
    """Return names and EAs for functions and (optionally) global symbols."""

    out: dict[str, list[dict[str, object]]] = {"symbols": []}
    error: dict[str, str | None] = {"message": None}

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
            return 1
        except Exception as e:
            error["message"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)

    if error["message"]:
        raise RuntimeError(error["message"])

    return out
