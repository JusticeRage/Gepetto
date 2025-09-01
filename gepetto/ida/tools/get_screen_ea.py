import json
import idaapi
import ida_kernwin

from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_screen_ea_tc(tc, messages):
    # The tool takes no arguments, but parse for forward compatibility.
    try:
        _ = json.loads(tc.function.arguments or "{}")
    except Exception:
        _ = {}

    ea = get_screen_ea()

    if ea is not None:
        payload = {"ok": True, "ea": ea}
    else:
        payload = {
            "ok": False,
            "error": "The cursor isn't set to a valid address. Click in a disassembly view first."
        }

    add_result_to_messages(messages, tc, payload)

def get_screen_ea() -> str | None:
    """Return the current effective address, or None if no valid EA."""
    ea = ida_kernwin.execute_sync(ida_kernwin.get_screen_ea, ida_kernwin.MFF_FAST)
    if ea == idaapi.BADADDR:
        return None
    return ea
