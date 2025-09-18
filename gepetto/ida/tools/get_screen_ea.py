import json
import idaapi

from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import safe_get_screen_ea, touch_last_ea


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
            "error": "No focused view: returning BADADDR. Provide EA explicitly or call an operation that sets last_ea."
        }

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

def get_screen_ea() -> int | None:
    """Return the current effective address (int), or None if no valid EA."""
    ea = safe_get_screen_ea()
    if ea == idaapi.BADADDR:
        return None
    touch_last_ea(ea)
    return int(ea)
