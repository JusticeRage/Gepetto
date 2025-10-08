import json

from gepetto.ida.utils.function_utils import resolve_ea
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

    name = args.get("name")

    try:
        ea = get_ea(name)
        payload = tool_result_payload({"ea": ea})
    except Exception as ex:
        payload = tool_error_payload(str(ex), name=name)

    add_result_to_messages(messages, tc, payload)


def get_ea(name: str) -> int:
    """Return the effective address for a symbol name."""
    return resolve_ea(name)
