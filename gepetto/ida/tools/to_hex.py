"""Tool to convert decimal integers to hexadecimal strings."""

import json

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_to_hex_tc(tc, messages):
    """Handle a `to_hex` tool call."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    value = args.get("value")

    try:
        hex_value = to_hex(value)
        payload = tool_result_payload({"hex": hex_value})
    except Exception as ex:
        payload = tool_error_payload(str(ex), value=value)

    add_result_to_messages(messages, tc, payload)


def to_hex(value) -> str:
    """Return the hexadecimal string for a decimal integer."""
    return hex(int(value))

