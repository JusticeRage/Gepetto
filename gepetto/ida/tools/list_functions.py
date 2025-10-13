import json

import ida_funcs
import ida_name
import idautils
import idaapi

from gepetto.ida.utils.function_helpers import get_func_name
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read



def handle_list_functions_tc(tc, messages):
    """Handle a tool call to enumerate functions."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    limit = int(args.get("limit", 256))
    offset = int(args.get("offset", 0))
    include_thunks = bool(args.get("include_thunks", True))

    try:
        data = list_functions(limit=limit, offset=offset, include_thunks=include_thunks)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            limit=limit,
            offset=offset,
            include_thunks=include_thunks,
        )

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_read
def _enumerate_functions(include_thunks: bool) -> list[dict[str, object]]:
    """Collect functions on the UI thread with optional thunk filtering."""

    idaapi.auto_wait()
    thunk_flag = getattr(ida_funcs, "FUNC_THUNK", 0)
    funcs: list[dict[str, object]] = []

    for ea in idautils.Functions():
        fn = ida_funcs.get_func(ea)
        if not fn:
            continue
        if not include_thunks and thunk_flag and (fn.flags & thunk_flag):
            continue
        name = get_func_name(fn) or ida_name.get_ea_name(fn.start_ea) or ""
        funcs.append({"ea": int(fn.start_ea), "name": name})

    return funcs


def list_functions(
    limit: int = 256,
    offset: int = 0,
    include_thunks: bool = True,
) -> dict[str, object]:
    """Return paginated functions from the IDA database."""
    if limit <= 0:
        raise ValueError("limit must be a positive integer")
    if offset < 0:
        raise ValueError("offset must be non-negative")

    funcs = _enumerate_functions(include_thunks=include_thunks)

    total = len(funcs)
    start = min(offset, total)
    end = min(start + limit, total)
    items = funcs[start:end]
    next_offset = end if end < total else None

    return {
        "total": total,
        "next_offset": next_offset,
        "items": items,
    }

