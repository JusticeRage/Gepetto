import json
from typing import Optional

import json
from typing import Optional

import ida_name
import ida_kernwin

from gepetto.ida.utils.ida9_utils import parse_ea, run_on_main_thread, touch_last_ea
from gepetto.ida.tools.function_utils import resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import add_result_to_messages


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
        result = rename_function(ea=ea, name=name, new_name=new_name)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


# -----------------------------------------------------------------------------


def rename_function(
    ea: Optional[int] = None,
    name: Optional[str] = None,
    new_name: Optional[str] = None,
) -> dict:
    """Rename a function by EA or name."""
    if not new_name:
        raise ValueError("new_name is required")

    f = resolve_func(ea=ea, name=name)
    old_name = name or get_func_name(f)
    ea = int(f.start_ea)
    touch_last_ea(ea)

    out = {"ok": False, "ea": ea, "old_name": old_name, "new_name": new_name}

    def _do():
        try:
            if not ida_name.set_name(ea, new_name):
                out["error"] = f"Failed to rename function {old_name!r}"
                return 0
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    if not run_on_main_thread(_do, write=True):
        if not out.get("error"):
            out["error"] = "Failed to execute on main thread"

    if not out["ok"]:
        raise ValueError(out.get("error", "Failed to rename function"))
    return out
