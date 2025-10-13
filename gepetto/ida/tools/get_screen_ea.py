import json

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import BADADDR, safe_get_screen_ea


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
    ea = safe_get_screen_ea()
    return None if ea == BADADDR else hex(ea)

