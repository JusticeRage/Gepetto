import json
from typing import Dict

import ida_bytes
import ida_kernwin

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_bytes_tc(tc, messages):
    """Handle tool call for get_bytes."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    size = args.get("size", 0x20)
    try:
        ea = parse_ea(ea)
        size = int(size)
        result = get_bytes(ea, size)
    except Exception as ex:
        result = {
            "ok": False,
            "error": str(ex),
            "ea": ea if isinstance(ea, int) else None,
            "size": size if isinstance(size, int) else None,
            "bytes": None,
        }

    add_result_to_messages(messages, tc, result)


# -----------------------------------------------------------------------------


def _read_bytes(ea: int, size: int) -> bytes:
    out = {"data": b""}

    def _do():
        out["data"] = ida_bytes.get_bytes(ea, size) or b""
        return 1

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out["data"]


def _format_bytes(bs: bytes) -> str:
    return " ".join(f"0x{b:02X}" for b in bs)


def get_bytes(ea: int, size: int = 0x20) -> Dict:
    """Return raw bytes starting at a given EA."""
    result = {
        "ok": False,
        "error": None,
        "ea": ea,
        "size": size,
        "bytes": None,
    }

    try:
        bs = _read_bytes(ea, size)
        result.update(ok=True, bytes=_format_bytes(bs))
    except Exception as e:
        result["error"] = str(e)

    return result
