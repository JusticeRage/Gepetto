import json

from gepetto.ida.tools.function_utils import resolve_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_ea_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    name = args.get("name")

    try:
        ea = get_ea(name)
        payload = {"ok": True, "ea": ea}
    except Exception as ex:
        payload = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, payload)


def get_ea(name: str) -> int:
    """Return the effective address for a symbol name."""
    return resolve_ea(name)
