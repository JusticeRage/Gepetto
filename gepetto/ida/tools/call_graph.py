import json
from typing import Any

import idaapi
import ida_funcs
import ida_name
import ida_xref
import ida_bytes

from gepetto.ida.utils.function_helpers import parse_ea
from gepetto.ida.tools.get_xrefs import get_xrefs_unified
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)

# -----------------------------------------------------------------------------

def handle_get_callers_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        try:
            ea = parse_ea(ea)
        except Exception:
            ea = None
    name = args.get("name")
    include_thunks = bool(args.get("include_thunks", True))

    try:
        data = get_callers(ea=ea, name=name, include_thunks=include_thunks)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea, name=name, include_thunks=include_thunks)

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

def get_callers(ea: int | None = None, name: str | None = None) -> dict[str, Any]:
    """
    Return unique caller functions that call the target function (by EA or name).
    Only call xrefs are considered.
    """
    if ea is not None:
        xrefs = get_xrefs_unified(scope="function", subject=str(ea), direction="to")
    elif name is not None:
        xrefs = get_xrefs_unified(scope="name", subject=name, direction="to")
    else:
        raise RuntimeError("Either ea or name must be provided")

    callers = set()
    for xref in xrefs["xrefs"]:
        callers.add({"from_ea": xref["from_ea"],
                     "to_ea": xref["to_ea"],
                     "from_func": xref["from_func"]})
