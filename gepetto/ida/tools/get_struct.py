import json

import ida_typeinf
import idaapi

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)

from gepetto.ida.utils.thread_helpers import ida_read


def handle_get_struct_tc(tc, messages):
    """Handle a tool call to fetch structure metadata."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    name = args.get("name")

    try:
        data = get_struct(name=name)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), name=name)

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_read
def _snapshot_struct(query: str) -> dict[str, object]:
    tif, resolved_name = _resolve_struct_tinfo(query)

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        raise RuntimeError(f"Failed to fetch fields for structure {resolved_name!r}.")

    fields = [_format_member(member) for member in _iter_udt_members(udt)]
    size_value = 0
    if hasattr(tif, "get_size"):
        raw_size = tif.get_size()
        badsize = getattr(idaapi, "BADSIZE", None)
        if badsize is not None and raw_size == badsize:
            raw_size = 0
        size_value = int(raw_size)

    return {
        "name": resolved_name,
        "size": size_value,
        "fields": fields,
    }


def _resolve_struct_tinfo(name: str) -> tuple[ida_typeinf.tinfo_t, str]:
    """Locate a structure type by name using ida_typeinf APIs."""

    til = ida_typeinf.get_idati()
    if til is None:
        raise RuntimeError("Local type library is unavailable.")

    candidates = _struct_name_candidates(name)
    decl_types = _decl_type_candidates()

    for candidate in candidates:
        result = _find_udt_in_til(til, candidate, decl_types)
        if result is not None:
            return result

    raise RuntimeError(f"Structure {name!r} was not found.")


def _find_udt_in_til(
    til: ida_typeinf.til_t,
    candidate: str,
    decl_types: tuple[int, ...],
) -> tuple[ida_typeinf.tinfo_t, str] | None:
    for decl_type in decl_types:
        tif = ida_typeinf.tinfo_t()
        try:
            found = tif.get_named_type(til, candidate, decl_type, True, True)
        except TypeError:  # Older SDKs omit the extended signature
            found = tif.get_named_type(til, candidate)
        if not found:
            continue
        if _tinfo_is_udt(tif):
            return tif, candidate

    tid = ida_typeinf.get_named_type_tid(candidate) if hasattr(ida_typeinf, "get_named_type_tid") else idaapi.BADADDR
    bad = {idaapi.BADADDR, getattr(idaapi, "BADNODE", idaapi.BADADDR)}
    if tid in bad:
        return None

    tif = ida_typeinf.tinfo_t(tid=tid)
    if _tinfo_is_udt(tif):
        resolved = ida_typeinf.get_tid_name(tid) if hasattr(ida_typeinf, "get_tid_name") else None
        display_name = resolved or candidate
        return tif, display_name
    return None


def _tinfo_is_udt(tif: ida_typeinf.tinfo_t) -> bool:
    if not tif or not tif.is_correct():
        return False
    return bool(tif.is_udt())


def _struct_name_candidates(name: str) -> tuple[str, ...]:
    base = str(name or "").strip()
    if not base:
        return tuple()

    variants = [base]
    lowered = base.lower()
    if not lowered.startswith("struct "):
        variants.append(f"struct {base}")
    if not lowered.startswith("union "):
        variants.append(f"union {base}")

    head, _, tail = base.partition(" ")
    if tail and head.lower() in {"struct", "union"}:
        variants.append(tail.strip())

    seen: set[str] = set()
    ordered: list[str] = []
    for variant in variants:
        if variant not in seen:
            seen.add(variant)
            ordered.append(variant)
    return tuple(ordered)


def _decl_type_candidates() -> tuple[int, ...]:
    values = [ida_typeinf.BTF_STRUCT, ida_typeinf.BTF_UNION]
    if hasattr(ida_typeinf, "BTF_TYPEDEF"):
        values.append(ida_typeinf.BTF_TYPEDEF)
    values.append(0)
    return tuple(values)


def _iter_udt_members(udt: ida_typeinf.udt_type_data_t):
    size_fn = getattr(udt, "size", None)
    if callable(size_fn):
        count = size_fn()
        getter = getattr(udt, "__getitem__", None)
        if callable(getter):
            for index in range(count):
                yield getter(index)
            return
        at_fn = getattr(udt, "at", None)
        if callable(at_fn):
            for index in range(count):
                yield at_fn(index)
            return
    for member in udt:
        yield member


def _format_member(member) -> dict[str, object]:
    """Return a serialisable description for a struct member."""

    name = getattr(member, "name", "") or ""
    offset_bits = getattr(member, "offset", None)
    if offset_bits is None:
        offset_bits = getattr(member, "soff", 0)
    offset = int(offset_bits // 8) if isinstance(offset_bits, (int, float)) else 0

    type_info = getattr(member, "type", None)
    type_text = ""
    if isinstance(type_info, ida_typeinf.tinfo_t):
        try:
            if hasattr(type_info, "dstr"):
                type_text = type_info.dstr()
            else:
                type_text = ida_typeinf.dstr_tinfo(type_info) or ""
        except Exception:
            type_text = ""

    return {"offset": offset, "type": str(type_text or ""), "name": name}


def get_struct(name: str | None) -> dict[str, object]:
    """Return metadata for a structure defined in the local types."""
    if not name or not str(name).strip():
        raise ValueError("name is required")

    query = str(name).strip()
    return _snapshot_struct(query)
