import json

import ida_kernwin
import ida_xref

from .function_utils import parse_ea as _parse_ea



def handle_get_xrefs_tc(tc, messages):
    """Handle a tool call to gather cross-references."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        ea = _parse_ea(ea)
    direction = args.get("direction", "from")

    try:
        result = get_xrefs(ea=ea, direction=direction)
    except Exception as ex:
        result = {
            "ok": False,
            "ea": ea,
            "direction": direction,
            "error": str(ex),
            "xrefs": [],
        }

    messages.append(
        {
            "role": "tool",
            "tool_call_id": tc.id,
            "content": json.dumps(result, ensure_ascii=False),
        }
    )


# -----------------------------------------------------------------------------


def get_xrefs(ea: int, direction: str) -> dict:
    """Collect cross-references to or from an address.

    Args:
        ea: Effective address to inspect.
        direction: 'to' for incoming, 'from' for outgoing references.
    """
    if ea is None:
        raise ValueError("ea is required")
    if direction not in ("to", "from"):
        raise ValueError("direction must be 'to' or 'from'")

    xrefs: list[int] = []

    def _do():
        if direction == "to":
            xr = ida_xref.get_first_xref_to(ea)
            while xr:
                xrefs.append(int(xr.frm))
                xr = ida_xref.get_next_xref_to(ea, xr)
        else:
            xr = ida_xref.get_first_xref_from(ea)
            while xr:
                xrefs.append(int(xr.to))
                xr = ida_xref.get_next_xref_from(ea, xr)
        return 1

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

    return {"ok": True, "ea": ea, "direction": direction, "xrefs": xrefs}
