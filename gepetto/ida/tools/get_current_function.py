import json

import ida_funcs

from gepetto.ida.utils.function_helpers import get_func_name
from gepetto.ida.utils.thread_helpers import BADADDR, ida_read, safe_get_screen_ea
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_get_current_function_tc(tc, messages):
    """Handle a tool call to fetch the function at the screen EA."""
    try:
        json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        # No arguments expected; ignore malformed payloads.
        pass

    try:
        data = get_current_function()
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex))

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_read
def _resolve_function_metadata(ea: int) -> dict[str, object]:
    fn = ida_funcs.get_func(ea)
    if not fn:
        raise RuntimeError(f"EA 0x{ea:X} is not inside a function.")
    return {
        "ea": int(ea),
        "start_ea": int(fn.start_ea),
        "end_ea": int(fn.end_ea),
        "name": get_func_name(fn) or "",
    }


def get_current_function() -> dict[str, object]:
    """Return metadata for the function under the current cursor."""
    screen_ea = safe_get_screen_ea()
    if screen_ea == BADADDR:
        raise RuntimeError("No active screen location is available.")

    return _resolve_function_metadata(screen_ea)

