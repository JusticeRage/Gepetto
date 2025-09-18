# gepetto/ida/tools/callgraph.py

import json
from typing import Dict, Optional, Iterable, Set

import idaapi
import ida_funcs
import ida_kernwin
import ida_name
import ida_xref
import ida_bytes

from gepetto.ida.utils.ida9_utils import run_on_main_thread, touch_last_ea
from gepetto.ida.tools.function_utils import parse_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import add_result_to_messages

# -----------------------------------------------------------------------------

def _is_thunk(fn_or_ea) -> bool:
    """Version-safe thunk check.
    - Accepts either a ``func_t`` or an EA
    - Prefer ``ida_funcs.is_thunk_func`` when available
    - Fallback to testing ``FUNC_THUNK`` flag using ``get_func_flags``
    """
    try:
        f = fn_or_ea if isinstance(fn_or_ea, ida_funcs.func_t) else ida_funcs.get_func(fn_or_ea)
    except Exception:
        f = None
    if not f:
        return False
    # Only rely on the official helper; do not maintain flag-bit fallbacks
    if hasattr(ida_funcs, "is_thunk_func"):
        try:
            return bool(ida_funcs.is_thunk_func(f))
        except Exception:
            return False
    return False

# -----------------------------------------------------------------------------

def handle_get_callers_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        try:
            ea = parse_ea(ea)
        except Exception:
            ea = None
    name = args.get("name")
    include_thunks = bool(args.get("include_thunks", True))

    try:
        result = get_callers(ea=ea, name=name, include_thunks=include_thunks)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

def handle_get_callees_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    if ea is not None:
        try:
            ea = parse_ea(ea)
        except Exception:
            ea = None
    name = args.get("name")
    only_direct = bool(args.get("only_direct", True))
    include_thunks = bool(args.get("include_thunks", True))

    try:
        result = get_callees(ea=ea, name=name, only_direct=only_direct, include_thunks=include_thunks)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)

# -----------------------------------------------------------------------------

def _is_call(xref_type: int) -> bool:
    # IDA: call near/far
    return xref_type in (ida_xref.fl_CN, ida_xref.fl_CF)

# -----------------------------------------------------------------------------

def _iter_func_items(fn: ida_funcs.func_t) -> Iterable[int]:
    ea = fn.start_ea
    end = fn.end_ea
    while ea < end:
        yield ea
        ea = ida_bytes.get_item_end(ea)

# -----------------------------------------------------------------------------

def _func_name(ea: int) -> str:
    f = ida_funcs.get_func(ea)
    if f:
        return get_func_name(f) or ""
    return ida_name.get_ea_name(ea) or ""

# -----------------------------------------------------------------------------

def _follow_thunk_once(fn: ida_funcs.func_t) -> Optional[int]:
    """
    Best-effort: if fn is a thunk, try to find its final code target.
    We look at outgoing code xrefs from the first item and pick the first call/jmp target.
    """
    if not fn or not _is_thunk(fn):
        return None
    start = fn.start_ea
    blk = ida_xref.xrefblk_t()
    if blk.first_from(start, ida_xref.XREF_FAR | ida_xref.XREF_USER | ida_xref.XREF_ALL):
        while True:
            # accept any code xref (call/jump), we'll filter callee function later
            if blk.iscode:
                return int(blk.to)
            if not blk.next_from():
                break
    # fallback: try next instruction/site if the first item didn't have an xref
    for item_ea in _iter_func_items(fn):
        if blk.first_from(item_ea, ida_xref.XREF_ALL):
            while True:
                if blk.iscode:
                    return int(blk.to)
                if not blk.next_from():
                    break
    return None

# -----------------------------------------------------------------------------

def _normalize_callee_ea(ea: int, include_thunks: bool) -> int:
    """
    If include_thunks=True and callee is a thunk, try to return the ultimate target's function start.
    Otherwise return the callee function start if available, or ea as-is.
    """
    f = ida_funcs.get_func(ea)
    if not f:
        return ea
    if include_thunks and _is_thunk(f):
        tgt = _follow_thunk_once(f)
        if tgt is not None:
            ft = ida_funcs.get_func(tgt)
            return ft.start_ea if ft else tgt
    return f.start_ea

# -----------------------------------------------------------------------------

def get_callers(ea: Optional[int] = None, name: Optional[str] = None,
                include_thunks: bool = True) -> Dict:
    """
    Return unique caller functions that call the target function (by EA or name).
    Only call xrefs are considered. If include_thunks is True and the target is a thunk,
    results will be keyed to the thunk's final target for normalization.
    """
    if ea is not None:
        ea = parse_ea(ea)
    out = {"ok": False, "target": {}, "callers": [], "error": None}

    def _do():
        try:
            idaapi.auto_wait()

            # Resolve target function
            fn = resolve_func(ea=ea if ea is not None else None,
                              name=name if name else None)
            target_fn = fn
            target_ea = fn.start_ea

            # Normalize to thunk target if requested (purely for reporting)
            norm_target_ea = _normalize_callee_ea(target_ea, include_thunks)
            norm_target_name = _func_name(norm_target_ea)

            out["target"] = {
                "ea": int(norm_target_ea),
                "name": norm_target_name,
            }
            touch_last_ea(norm_target_ea)

            # Collect callers: code xrefs TO the (possibly normalized) callee start
            callee_start = norm_target_ea
            blk = ida_xref.xrefblk_t()
            callers: Set[int] = set()
            if blk.first_to(callee_start, ida_xref.XREF_ALL):
                while True:
                    if blk.iscode and _is_call(blk.type):
                        cf = ida_funcs.get_func(blk.frm)
                        if cf:
                            callers.add(cf.start_ea)
                    if not blk.next_to():
                        break

            out["callers"] = [
                {"ea": int(c_ea), "name": _func_name(c_ea)}
                for c_ea in sorted(callers)
            ]
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    run_on_main_thread(_do, write=False)
    return out

# -----------------------------------------------------------------------------

def get_callees(ea: Optional[int] = None, name: Optional[str] = None,
                only_direct: bool = True, include_thunks: bool = True) -> Dict:
    """
    Return unique callee functions reached from the target function.
    - only_direct=True: only consider direct code call xrefs (ignore data/indirect).
    - include_thunks=True: normalize callees that are thunks to their ultimate targets.
    """
    if ea is not None:
        ea = parse_ea(ea)
    out = {"ok": False, "source": {}, "callees": [], "error": None}

    def _do():
        try:
            idaapi.auto_wait()

            # Resolve source function (where we look for calls FROM)
            fn = resolve_func(ea=ea if ea is not None else None,
                              name=name if name else None)
            src_ea = fn.start_ea
            touch_last_ea(src_ea)
            out["source"] = {"ea": int(src_ea), "name": _func_name(src_ea)}

            # Walk each item in the function and gather outgoing call xrefs
            callees: Set[int] = set()
            blk = ida_xref.xrefblk_t()
            for item_ea in _iter_func_items(fn):
                if blk.first_from(item_ea, ida_xref.XREF_ALL):
                    while True:
                        if blk.iscode:
                            if _is_call(blk.type):
                                tgt = _normalize_callee_ea(int(blk.to), include_thunks)
                                # When only_direct=True, we already have direct call sites
                                # (indirect through data wouldn't appear as code call xref).
                                callees.add(tgt)
                        elif not only_direct:
                            # Non-code xrefs FROM a site in a function are uncommon but keep the gate.
                            pass
                        if not blk.next_from():
                            break

            out["callees"] = [
                {"ea": int(t_ea), "name": _func_name(t_ea)}
                for t_ea in sorted(callees)
            ]
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    run_on_main_thread(_do, write=False)
    return out
