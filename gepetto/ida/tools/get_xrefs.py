import json
from collections.abc import Iterable
from typing import Any

import idaapi
import ida_bytes
import ida_funcs
import ida_name
import ida_xref

from gepetto.ida.utils.function_helpers import parse_ea, resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)

from gepetto.ida.utils.thread_helpers import ida_read

def handle_get_xrefs_tc(tc, messages):
    """Handle a tool call to fetch cross-references (EA/function/name)."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    # Primary args
    scope = args.get("scope", "ea")
    subject = args.get("subject")

    direction = args.get("direction", "both")
    kind = args.get("kind", "both")
    only_calls = bool(args.get("only_calls", False))
    exclude_flow = bool(args.get("exclude_flow", False))
    collapse_by = args.get("collapse_by", "site")
    enrich_names = bool(args.get("enrich_names", True))

    try:
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("subject must be a non-empty string")

        normalized_subject = subject.strip()

        data = get_xrefs_unified(
            scope=scope,
            subject=normalized_subject,
            direction=direction,
            kind=kind,
            only_calls=only_calls,
            exclude_flow=exclude_flow,
            collapse_by=collapse_by,
            enrich_names=enrich_names,
        )
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            scope=scope,
            subject=subject,
            direction=direction,
            kind=kind,
        )

    add_result_to_messages(messages, tc, payload)

# -----------------------------------------------------------------------------

@ida_read
def _gather_xrefs(
    scope: str,
    subject: str,
    direction: str,
    kind: str,
    only_calls: bool,
    exclude_flow: bool,
    collapse_by: str | None,
    enrich_names: bool,
) -> dict[str, Any]:
    idaapi.auto_wait()

    if scope == "ea":
        target_ea = parse_ea(subject)
        f = ida_funcs.get_func(target_ea)
        subject_kind = "function" if f and f.start_ea == target_ea else "item"
    elif scope == "function":
        f = resolve_func(ea=parse_ea(subject))
        target_ea = f.start_ea
        subject_kind = "function"
    else:  # scope == "name"
        name_ea = resolve_ea(subject)
        f = ida_funcs.get_func(name_ea)
        if f:
            target_ea = f.start_ea
            subject_kind = "function"
        else:
            target_ea = name_ea
            subject_kind = "item"

    subj_name = _ea_func_name(target_ea) if enrich_names else None

    filter_code = kind == "code"
    filter_data = kind == "data"

    out: dict[str, Any] = {
        "scope": scope,
        "subject": {"ea": int(target_ea), "name": subj_name or "", "kind": subject_kind},
        "direction": direction,
        "filters": {},
        "xrefs": [],
        "stats": {},
    }

    items: Iterable[int]
    if subject_kind == "function":
        fn = ida_funcs.get_func(target_ea)
        items = _iter_func_items(fn)
    else:
        items = (target_ea,)

    results = []
    for item_ea in items:
        if direction in {"to", "both"}:
            for frm_ea, t, iscode in _collect_xrefs_to(item_ea, ida_xref.XREF_ALL):
                results.append(("to", frm_ea, item_ea, t, iscode))
        if direction in {"from", "both"}:
            for to_ea, t, iscode in _collect_xrefs_from(item_ea, ida_xref.XREF_ALL):
                results.append(("from", item_ea, to_ea, t, iscode))

    filtered = []
    for dirn, frm, to, t, iscode in results:
        kind_label = "code" if iscode else "data"
        if filter_code and not iscode:
            continue
        if filter_data and iscode:
            continue
        if only_calls and not (iscode and _is_call(t)):
            continue
        if exclude_flow and (iscode and _is_flow(t)):
            continue
        filtered.append((dirn, frm, to, t, kind_label))

    seen = set()
    collapsed = []
    for dirn, frm, to, t, kind_label in filtered:
        if collapse_by == "pair":
            key = (frm, to)
        elif collapse_by == "from_func":
            key = (
                ida_funcs.get_func(frm).start_ea if ida_funcs.get_func(frm) else frm,
                to,
            )
        elif collapse_by == "to_func":
            key = (
                frm,
                ida_funcs.get_func(to).start_ea if ida_funcs.get_func(to) else to,
            )
        else:
            key = (dirn, frm, to, t, kind_label)
        if key in seen:
            continue
        seen.add(key)

        rec = {
            "from_ea": int(frm),
            "to_ea": int(to),
            "direction": dirn,
            "kind": kind_label,
            "type": int(t),
        }
        if enrich_names:
            rec["from_func"] = _ea_func_name(frm) or ""
            rec["to_func"] = _ea_func_name(to) or ""
        collapsed.append(rec)

    out["xrefs"] = collapsed
    out["stats"] = {
        "sites": len(filtered),
        "unique": len(collapsed),
    }
    out["filters"] = {
        "kind": kind,
        "only_calls": only_calls,
        "exclude_flow": exclude_flow,
        "collapse_by": collapse_by or "site",
    }
    return out


def _is_call(xref_type: int) -> bool:
    # IDA uses fl_* constants in ida_xref; calls are typically fl_CN/fl_CF (near/far)
    return xref_type in (ida_xref.fl_CN, ida_xref.fl_CF)

# -----------------------------------------------------------------------------

def _is_flow(xref_type: int) -> bool:
    # Jumps/flow: near/far jump & ordinary flow
    return xref_type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F)

# -----------------------------------------------------------------------------

def _iter_func_items(fn: ida_funcs.func_t) -> Iterable[int]:
    ea = fn.start_ea
    while ea < fn.end_ea:
        yield ea
        ea = ida_bytes.get_item_end(ea)

# -----------------------------------------------------------------------------

def _collect_xrefs_to(ea: int, kinds_mask=ida_xref.XREF_ALL) -> Iterable[tuple[int, int, bool]]:
    blk = ida_xref.xrefblk_t()
    if blk.first_to(ea, kinds_mask):
        while True:
            yield (blk.frm, blk.type, bool(blk.iscode))
            if not blk.next_to():
                break

# -----------------------------------------------------------------------------

def _collect_xrefs_from(ea: int, kinds_mask=ida_xref.XREF_ALL) -> Iterable[tuple[int, int, bool]]:
    blk = ida_xref.xrefblk_t()
    if blk.first_from(ea, kinds_mask):
        while True:
            yield (blk.to, blk.type, bool(blk.iscode))
            if not blk.next_from():
                break

# -----------------------------------------------------------------------------

def _ea_func_name(ea: int) -> str | None:
    f = ida_funcs.get_func(ea)
    if f:
        return get_func_name(f) or None
    name = ida_name.get_ea_name(ea)
    return name or None

# -----------------------------------------------------------------------------

def _normalize_kind(kind_value: str | None) -> str:
    """Validate the requested xref kind filter."""
    if not kind_value:
        return "both"
    kind_text = str(kind_value).lower()
    if kind_text not in {"code", "data", "both"}:
        raise ValueError("kind must be 'code', 'data', or 'both'")
    return kind_text

# -----------------------------------------------------------------------------

def get_xrefs_unified(
        scope: str,
        subject: str,
        direction: str = "both",
        kind: str | None = "both",
        only_calls: bool = False,
        exclude_flow: bool = False,
        collapse_by: str | None = None,
        enrich_names: bool = True,
) -> dict[str, Any]:
    """Return cross-reference information for the requested scope."""
    if direction not in {"to", "from", "both"}:
        raise ValueError("direction must be 'to'|'from'|'both'")
    if scope not in {"ea", "function", "name"}:
        raise ValueError("scope must be 'ea'|'function'|'name'")

    normalized_kind = _normalize_kind(kind)
    return _gather_xrefs(
        scope=scope,
        subject=subject,
        direction=direction,
        kind=normalized_kind,
        only_calls=only_calls,
        exclude_flow=exclude_flow,
        collapse_by=collapse_by,
        enrich_names=enrich_names,
    )
