import json
from typing import Dict

import ida_lines
import ida_kernwin

from gepetto.ida.utils.ida9_utils import parse_ea, run_on_main_thread
from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import touch_last_ea


def handle_get_disasm_tc(tc, messages):
    """Handle tool call for get_disasm."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    try:
        ea = parse_ea(ea)
        touch_last_ea(ea)
        result = get_disasm(ea)
    except Exception as ex:
        result = {
            "ok": False,
            "error": str(ex),
            "ea": ea if isinstance(ea, int) else None,
            "disasm": None,
        }

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

def _get_disasm_line(ea: int) -> str:
    out = {"text": ""}

    def _do():
        out["text"] = ida_lines.generate_disasm_line(ea, 0) or ""
        return 1

    run_on_main_thread(_do, write=False)
    return out["text"]

# -----------------------------------------------------------------------------

def get_disasm(ea: int) -> Dict:
    """Return the disassembly line at a given EA.

    Parameters:
        ea (int): Effective address to disassemble.

    Returns:
        dict: {
            "ok": bool,
            "error": str | None,
            "ea": int,
            "disasm": str | None,
        }
    """
    ea = parse_ea(ea)
    result = {
        "ok": False,
        "error": None,
        "ea": ea,
        "disasm": None,
    }

    try:
        line = _get_disasm_line(ea)
        result.update(
            ok=True,
            disasm=line,
        )
    except Exception as e:
        result["error"] = str(e)

    return result
