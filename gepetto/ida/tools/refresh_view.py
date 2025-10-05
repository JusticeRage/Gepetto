import json

import ida_kernwin

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_refresh_view_tc(tc, messages):
    """Handle a tool call to refresh the current IDA view."""
    # The tool takes no arguments but parse for forward compatibility.
    _ = json.loads(tc.function.arguments or "{}")

    try:
        data = refresh_view()
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex))

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

def refresh_view() -> dict:
    """Refresh the current IDA disassembly view."""

    error: dict[str, str | None] = {"message": None}

    def _do():
        try:
            ida_kernwin.refresh_idaview_anyway()
            return 1
        except Exception as e:
            error["message"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

    if error["message"]:
        raise RuntimeError(error["message"])
    return {"status": "refreshed"}