+44-0
import json

import ida_kernwin

from gepetto.ida.tools.tools import add_result_to_messages


def handle_refresh_view_tc(tc, messages):
    """Handle a tool call to refresh the current IDA view."""
    # The tool takes no arguments but parse for forward compatibility.
    _ = json.loads(tc.function.arguments or "{}")

    try:
        result = refresh_view()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

def refresh_view() -> dict:
    """Refresh the current IDA disassembly view."""
    out = {"ok": False}

    def _do():
        try:
            ida_kernwin.refresh_idaview_anyway()
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

    if not out["ok"]:
        raise ValueError(out.get("error", "Failed to refresh view"))
    return out