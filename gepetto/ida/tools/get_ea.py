import json

from gepetto.ida.utils.function_helpers import resolve_ea
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_get_ea_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    raw_name = args.get("name")
    name = raw_name if isinstance(raw_name, str) else None

    try:
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("name must be a non-empty string")
        normalized = raw_name.strip()
        ea = get_ea(normalized)
        payload = tool_result_payload({"ea": ea})
    except Exception as ex:
        payload = tool_error_payload(str(ex), name=name)

    add_result_to_messages(messages, tc, payload)


def get_ea(name: str) -> int:
    """Return the effective address for a symbol name."""
    return resolve_ea(name)
