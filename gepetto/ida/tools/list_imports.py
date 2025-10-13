import json

import ida_nalt
import idaapi

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read



def handle_list_imports_tc(tc, messages):
    """Handle a tool call to enumerate imports."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    limit = int(args.get("limit", 256))
    offset = int(args.get("offset", 0))
    module_filter = args.get("module_filter")

    try:
        data = list_imports(limit=limit, offset=offset, module_filter=module_filter)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            limit=limit,
            offset=offset,
            module_filter=module_filter,
        )

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_read
def _collect_imports() -> list[dict[str, object]]:
    """Snapshot the import table on the IDA UI thread."""

    idaapi.auto_wait()
    results: list[dict[str, object]] = []
    qty = ida_nalt.get_import_module_qty()

    for mod_idx in range(qty):
        module = ida_nalt.get_import_module_name(mod_idx) or ""

        def _cb(ea, name, ordinal):
            results.append(
                {
                    "ea": int(ea),
                    "name": name or f"ord_{ordinal}",
                    "module": module,
                }
            )
            return 1

        ida_nalt.enum_import_names(mod_idx, _cb)

    return results




def list_imports(
    limit: int = 256,
    offset: int = 0,
    module_filter: str | None = None,
) -> dict[str, object]:
    """Return paginated import entries with optional module filtering."""
    if limit <= 0:
        raise ValueError("limit must be a positive integer")
    if offset < 0:
        raise ValueError("offset must be non-negative")

    imports = _collect_imports()
    filter_norm = (module_filter or "").strip().casefold()
    if filter_norm:
        imports = [item for item in imports if filter_norm in (item["module"] or "").casefold()]

    total = len(imports)
    start = min(offset, total)
    end = min(start + limit, total)
    items = imports[start:end]
    next_offset = end if end < total else None

    return {
        "total": total,
        "next_offset": next_offset,
        "items": items,
    }
