import json

import ida_funcs
import ida_name
import idautils

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read



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


@ida_read
def _enumerate_symbols(prefix: str, include_globals: bool) -> list[dict[str, object]]:
    pref = prefix or ""
    results: list[dict[str, object]] = []

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

    return results


def list_symbols(prefix: str = "", include_globals: bool = False) -> dict:
    """Return names and EAs for functions and (optionally) global symbols."""
    symbols = _enumerate_symbols(prefix=prefix, include_globals=include_globals)
    return {"symbols": symbols}
