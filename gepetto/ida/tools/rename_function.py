import json
import re

import ida_name
import ida_kernwin

from gepetto.ida.utils.function_utils import parse_ea, resolve_ea, resolve_func, get_func_name
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

    error: dict[str, str | None] = {"message": None}
    applied_name = new_name

    def _do():
        try:
            nonlocal applied_name
            flags = ida_name.SN_FORCE | getattr(ida_name, "SN_NOWARN", 0)
            if ida_name.set_name(ea, applied_name, flags):
                return 1
            sanitized = _sanitize_identifier(applied_name)
            if sanitized != applied_name and ida_name.set_name(ea, sanitized, flags):
                applied_name = sanitized
                return 1
            error["message"] = f"Failed to rename function {old_name!r} -> {applied_name!r}"
            return 0
        except Exception as e:
            error["message"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)

    if error["message"]:
        raise RuntimeError(error["message"])

    result = {"ea": ea, "old_name": old_name, "new_name": applied_name}
    if applied_name != new_name:
        result["requested_name"] = new_name
    return result
