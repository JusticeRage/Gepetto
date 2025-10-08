import json

import ida_lines
import ida_kernwin

from gepetto.ida.utils.function_utils import parse_ea
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_get_disasm_tc(tc, messages):
    """Handle tool call for get_disasm."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    try:
        ea = parse_ea(ea)
        data = get_disasm(ea)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            ea=ea if isinstance(ea, int) else None,
        )

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

def _get_disasm_line(ea: int) -> str:
    out = {"text": ""}

    def _do():
        out["text"] = ida_lines.generate_disasm_line(ea, 0) or ""
        return 1

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out["text"]

# -----------------------------------------------------------------------------

def get_disasm(ea: int) -> dict[str, int | str]:
    """Return the disassembly line at a given EA."""

    line = _get_disasm_line(ea)
    return {
        "ea": ea,
        "disasm": line,
    }
