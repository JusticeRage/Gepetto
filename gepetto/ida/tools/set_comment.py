import json

import idc


from gepetto.ida.utils.function_helpers import parse_ea
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_write

def handle_set_comment_tc(tc, messages):
    """Handle a tool call to apply a comment."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    ea_arg = args.get("ea")
    comment = args.get("comment")

    try:
        ea = parse_ea(ea_arg)
        data = set_comment(ea=ea, comment=comment)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea_arg, comment=comment)

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_write
def _apply_comment(ea: int, comment: str) -> None:
    if not idc.set_func_cmt(ea, comment, False):
        raise RuntimeError("Failed to set comment")


def set_comment(ea: int, comment: str | None) -> dict[str, object]:
    """Set a non-repeatable comment at the given EA."""
    if comment is None:
        raise ValueError("comment is required")

    normalized = comment.rstrip("\r\n")
    _apply_comment(ea, normalized)
    return {"ok": True, "ea": ea}
