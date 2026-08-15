"""Model-tool adapter for bounded caller/callee context."""

import json

from gepetto.ida.call_graph import collect_call_graph_context
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def get_call_graph_context(
    ea=None,
    direction="both",
    max_depth=None,
    max_functions=None,
    max_chars_per_function=None,
):
    """Collect relationship evidence without changing collector defaults."""
    bounds = {
        name: value
        for name, value in {
            "max_depth": max_depth,
            "max_functions": max_functions,
            "max_chars_per_function": max_chars_per_function,
        }.items()
        if value is not None
    }
    return collect_call_graph_context(ea=ea, direction=direction, **bounds)


def handle_get_call_graph_context_tc(tc, messages):
    """Handle a model request for bounded caller/callee pseudocode."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    try:
        result = get_call_graph_context(
            ea=args.get("ea"),
            direction=args.get("direction", "both"),
            max_depth=args.get("max_depth"),
            max_functions=args.get("max_functions"),
            max_chars_per_function=args.get("max_chars_per_function"),
        )
        payload = tool_result_payload(result)
    except Exception as exc:
        payload = tool_error_payload(
            str(exc),
            ea=args.get("ea"),
            direction=args.get("direction", "both"),
        )

    add_result_to_messages(messages, tc, payload)
