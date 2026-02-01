import json

import ida_lines
import idautils

from gepetto.ida.utils.function_helpers import get_func_name, parse_ea, resolve_func
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read


def handle_disasm_function_tc(tc, messages):
    """Handle tool call for disasm_function."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    name = args.get("name")
    try:
        data = disasm_function(ea=ea, name=name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea, name=name)

    add_result_to_messages(messages, tc, payload)


@ida_read
def _collect_disasm_lines(func_start_ea: int):
    lines = []
    for item_ea in idautils.FuncItems(func_start_ea):
        line = ida_lines.tag_remove(ida_lines.generate_disasm_line(item_ea, 0)) or ""
        if not line:
            continue
        lines.append(f"{int(item_ea):#x}: {line}")
    return lines


def disasm_function(ea=None, name=None) -> dict:
    """Return the disassembly for every item in a function."""
    target_ea = None
    if ea is not None:
        target_ea = parse_ea(ea)
    if target_ea is None and not name:
        raise ValueError("Provide either ea or name")

    func = resolve_func(ea=target_ea, name=name)
    func_name = get_func_name(func)
    lines = _collect_disasm_lines(int(func.start_ea))

    return {
        "function": {
            "name": func_name,
            "start_ea": int(func.start_ea),
            "end_ea": int(func.end_ea),
        },
        "disasm": "\n".join(lines),
    }
