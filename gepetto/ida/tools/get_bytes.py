import json

import ida_bytes

from gepetto.ida.utils.function_helpers import parse_ea
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read


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
        data = get_bytes(ea, size)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            ea=ea if isinstance(ea, int) else None,
            size=size if isinstance(size, int) else None,
        )

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_read
def _read_bytes(ea: int, size: int) -> bytes:
    return ida_bytes.get_bytes(ea, size) or b""


def _format_bytes(bs: bytes) -> str:
    return " ".join(f"0x{b:02X}" for b in bs)


def get_bytes(ea: int, size: int = 0x20) -> dict[str, int | str]:
    """Return raw bytes starting at a given EA."""

    if size <= 0:
        raise ValueError("size must be a positive integer")

    bs = _read_bytes(ea, size)
    return {
        "ea": ea,
        "size": size,
        "bytes": _format_bytes(bs),
    }
