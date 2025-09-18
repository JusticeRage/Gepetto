import json
from typing import Dict, Optional, Iterable, Tuple

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_xref

from gepetto.ida.utils.ida9_utils import parse_ea, touch_last_ea, run_on_main_thread
from gepetto.ida.tools.function_utils import resolve_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import add_result_to_messages

def handle_get_xrefs_tc(tc, messages):
    """Handle a tool call to fetch cross-references (EA/function/name)."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    # Primary args
    scope = args.get("scope", "ea")
    subject = args.get("subject")

    # Backward-compat inputs (prefer explicit 'subject')
    if subject is None:
        if "ea" in args and args["ea"] is not None:
            subject = str(args["ea"])
            if scope not in ("ea", "function"):
                scope = "ea"
        elif "name" in args and args["name"]:
            subject = args["name"]
            scope = "name"

    direction     = args.get("direction", "both")
    only_code     = bool(args.get("only_code", False))
    only_data     = bool(args.get("only_data", False))
    only_calls    = bool(args.get("only_calls", False))
    exclude_flow  = bool(args.get("exclude_flow", False))
    collapse_by   = args.get("collapse_by", "site")
    enrich_names  = bool(args.get("enrich_names", True))

    try:
        result = get_xrefs_unified(
            scope=scope,
            subject=subject,
            direction=direction,
            only_code=only_code,
            only_data=only_data,
            only_calls=only_calls,
            exclude_flow=exclude_flow,
            collapse_by=collapse_by,
            enrich_names=enrich_names,
        )
    except Exception as ex:
        result = {"ok": False, "error": str(ex), "scope": scope, "subject": subject, "direction": direction}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

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

def _collect_xrefs_to(ea: int, kinds_mask=ida_xref.XREF_ALL) -> Iterable[Tuple[int, int, bool]]:
    blk = ida_xref.xrefblk_t()
    if blk.first_to(ea, kinds_mask):
        while True:
            yield (blk.frm, blk.type, bool(blk.iscode))
            if not blk.next_to():
                break

# -----------------------------------------------------------------------------

def _collect_xrefs_from(ea: int, kinds_mask=ida_xref.XREF_ALL) -> Iterable[Tuple[int, int, bool]]:
    blk = ida_xref.xrefblk_t()
    if blk.first_from(ea, kinds_mask):
        while True:
            yield (blk.to, blk.type, bool(blk.iscode))
            if not blk.next_from():
                break

# -----------------------------------------------------------------------------

def _ea_func_name(ea: int) -> Optional[str]:
    f = ida_funcs.get_func(ea)
    if f:
        return get_func_name(f) or None
    name = ida_name.get_ea_name(ea)
    return name or None

# -----------------------------------------------------------------------------

def get_xrefs_unified(
        scope: str,
        subject: str,
        direction: str = "both",
        only_code: bool = False,
        only_data: bool = False,
        only_calls: bool = False,
        exclude_flow: bool = False,
        collapse_by: Optional[str] = None,   # "site"|"pair"|"from_func"|"to_func"
        enrich_names: bool = True,
) -> Dict:
    """
    scope: "ea" | "function" | "name"
    subject: EA (int or hex str) or name (if scope=="name")
    direction: "to" | "from" | "both"
    """
    if direction not in {"to","from","both"}:
        raise ValueError("direction must be 'to'|'from'|'both'")
    if scope not in {"ea","function","name"}:
        raise ValueError("scope must be 'ea'|'function'|'name'")

    out = {"ok": False, "scope": scope, "subject": {}, "direction": direction, "filters": {}, "xrefs": [], "stats": {}}

    def _do():
        try:
            idaapi.auto_wait()

            # Resolve subject -> (mode, ea, maybe fn)
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
            out["subject"] = {"ea": int(target_ea), "name": subj_name or "", "kind": subject_kind}
            touch_last_ea(target_ea)

            # Build list of items to scan
            items: Iterable[int]
            if subject_kind == "function":
                fn = ida_funcs.get_func(target_ea)
                items = _iter_func_items(fn)
            else:
                items = (target_ea,)

            kinds_mask = ida_xref.XREF_ALL
            results = []

            # Gather
            for item_ea in items:
                if direction in {"to","both"}:
                    for frm_ea, t, iscode in _collect_xrefs_to(item_ea, kinds_mask):
                        results.append(("to", frm_ea, item_ea, t, iscode))
                if direction in {"from","both"}:
                    for to_ea, t, iscode in _collect_xrefs_from(item_ea, kinds_mask):
                        results.append(("from", item_ea, to_ea, t, iscode))

            # Filter
            filtered = []
            for dirn, frm, to, t, iscode in results:
                kind = "code" if iscode else "data"
                if only_code and not iscode:
                    continue
                if only_data and iscode:
                    continue
                if only_calls and not (iscode and _is_call(t)):
                    continue
                if exclude_flow and (iscode and _is_flow(t)):
                    continue
                filtered.append((dirn, frm, to, t, kind))

            # Collapse
            seen = set()
            collapsed = []
            for dirn, frm, to, t, kind in filtered:
                if collapse_by == "pair":
                    key = (frm, to)
                elif collapse_by == "from_func":
                    key = (ida_funcs.get_func(frm).start_ea if ida_funcs.get_func(frm) else frm,
                           to)
                elif collapse_by == "to_func":
                    key = (frm,
                           ida_funcs.get_func(to).start_ea if ida_funcs.get_func(to) else to)
                else:  # "site" or None: keep every site
                    key = (dirn, frm, to, t, kind)
                if key in seen:
                    continue
                seen.add(key)

                rec = {
                    "from_ea": int(frm),
                    "to_ea": int(to),
                    "direction": dirn,
                    "kind": kind,
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
                "only_code": only_code,
                "only_data": only_data,
                "only_calls": only_calls,
                "exclude_flow": exclude_flow,
                "collapse_by": collapse_by or "site",
            }
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    run_on_main_thread(_do, write=False)
    return out
