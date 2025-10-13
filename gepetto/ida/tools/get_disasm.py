import json

import ida_lines

from gepetto.ida.utils.function_helpers import parse_ea
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read


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

@ida_read
def _get_disasm_line(ea: int) -> str:
    return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0)) or ""

# -----------------------------------------------------------------------------

def get_disasm(ea: int) -> dict[str, int | str]:
    """Return the disassembly line at a given EA."""

    line = _get_disasm_line(ea)
    return {
        "ea": ea,
        "disasm": line,
    }
