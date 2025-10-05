import json
import idaapi
import ida_kernwin

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_get_screen_ea_tc(tc, messages):
    # The tool takes no arguments, but parse for forward compatibility.
    try:
        _ = json.loads(tc.function.arguments or "{}")
    except Exception:
        _ = {}

    ea = get_screen_ea()

    if ea is not None:
        payload = tool_result_payload({"ea": ea})
    else:
        payload = tool_error_payload(
            "The cursor isn't set to a valid address. Click in a disassembly view first."
        )

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

def get_screen_ea() -> str | None:
    ea = idaapi.BADADDR
    def _cb():
        nonlocal ea
        ea = ida_kernwin.get_screen_ea()
        return 0
    ida_kernwin.execute_sync(_cb, ida_kernwin.MFF_READ)
    return None if ea == idaapi.BADADDR else hex(ea)

