import json
import re

import ida_name

from gepetto.ida.utils.function_helpers import parse_ea, resolve_ea, resolve_func, get_func_name
from gepetto.ida.utils.thread_helpers import ida_write
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)

def _sanitize_identifier(candidate: str) -> str:
    """Convert arbitrary text into an IDA-safe identifier."""
    cleaned = re.sub(r"\W+", "_", candidate.strip())
    if not cleaned:
        cleaned = "func"
    if cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned[: ida_name.MAXNAMELEN]


def handle_rename_function_tc(tc, messages):
    """Handle a tool call to rename a function."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        ea = parse_ea(ea)
    name = args.get("name")
    new_name = args.get("new_name")

    try:
        data = rename_function(ea=ea, name=name, new_name=new_name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea, name=name, new_name=new_name)
    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


def rename_function(
    ea: int | None = None,
    name: str | None = None,
    new_name: str | None = None,
) -> dict:
    """Rename a function by EA or name."""
    if not new_name:
        raise ValueError("new_name is required")

    f = resolve_func(ea=ea, name=name)
    old_name = name or get_func_name(f)
    ea = int(f.start_ea)

    applied_name = _apply_function_rename(ea, old_name, new_name)

    result = {"ea": ea, "old_name": old_name, "new_name": applied_name}
    if applied_name != new_name:
        result["requested_name"] = new_name
    return result


@ida_write
def _apply_function_rename(ea: int, old_name: str, desired_name: str) -> str:
    flags = ida_name.SN_FORCE | getattr(ida_name, "SN_NOWARN", 0)
    if ida_name.set_name(ea, desired_name, flags):
        return desired_name

    sanitized = _sanitize_identifier(desired_name)
    if sanitized != desired_name and ida_name.set_name(ea, sanitized, flags):
        return sanitized

    if sanitized != desired_name:
        raise RuntimeError(
            f"Failed to rename function {old_name!r} -> {desired_name!r} (sanitized {sanitized!r})"
        )
    raise RuntimeError(f"Failed to rename function {old_name!r} -> {desired_name!r}")
