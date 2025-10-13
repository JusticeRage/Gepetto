import json
from collections.abc import Iterable
from typing import Any

import idaapi
import ida_funcs
import ida_name
import ida_xref
import ida_bytes

from gepetto.ida.utils.function_helpers import parse_ea, resolve_func, get_func_name
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read

# Compatibility with older IDA versions where is_thunk_func is available
try:
    _HAS_IS_THUNK = hasattr(ida_funcs, "is_thunk_func") and callable(ida_funcs.is_thunk_func)
except Exception:
    _HAS_IS_THUNK = False

# -----------------------------------------------------------------------------

def _is_thunk_func(fn: ida_funcs.func_t) -> bool:
    """
    Version-safe thunk check:
    - prefer ida_funcs.is_thunk_func if available
    - else test FUNC_THUNK in fn.flags
    """
    if not fn:
        return False
    if _HAS_IS_THUNK:
        try:
            return bool(ida_funcs.is_thunk_func(fn))
        except Exception:
            pass
    # Fallback: flags bit test
    return bool(getattr(fn, "flags", 0) & getattr(ida_funcs, "FUNC_THUNK", 0))

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
        data = get_callers(ea=ea, name=name, include_thunks=include_thunks)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), ea=ea, name=name, include_thunks=include_thunks)

    add_result_to_messages(messages, tc, payload)

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
        data = get_callees(ea=ea, name=name, only_direct=only_direct, include_thunks=include_thunks)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            ea=ea,
            name=name,
            only_direct=only_direct,
            include_thunks=include_thunks,
        )

    add_result_to_messages(messages, tc, payload)

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

def _follow_thunk_once(fn: ida_funcs.func_t) -> int | None:
    """
    Best-effort: if fn is a thunk, try to find its final code target.
    We look at outgoing code xrefs from the first item and pick the first call/jmp target.
    """
    if not fn or not _is_thunk_func(fn):
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
    if include_thunks and _is_thunk_func(f):
        tgt = _follow_thunk_once(f)
        if tgt is not None:
            ft = ida_funcs.get_func(tgt)
            return ft.start_ea if ft else tgt
    return f.start_ea

# -----------------------------------------------------------------------------

def _ea_func_name(ea: int) -> str:
    f = ida_funcs.get_func(ea)
    if f:
        try:
            return get_func_name(f) or ""
        except Exception:
            pass
    name = ida_name.get_ea_name(ea)
    return name or ""

# -----------------------------------------------------------------------------

@ida_read
def _collect_callers(ea: int | None, name: str | None, include_thunks: bool) -> dict[str, Any]:
    idaapi.auto_wait()

    fn = resolve_func(ea=ea, name=name)
    target_ea = fn.start_ea

    norm_target_ea = _normalize_callee_ea(target_ea, include_thunks)
    norm_target_name = _ea_func_name(norm_target_ea)

    blk = ida_xref.xrefblk_t()
    callers: set[int] = set()
    if blk.first_to(norm_target_ea, ida_xref.XREF_ALL):
        while True:
            if blk.iscode and _is_call(blk.type):
                cf = ida_funcs.get_func(blk.frm)
                if cf:
                    callers.add(cf.start_ea)
            if not blk.next_to():
                break

    return {
        "target": {"ea": int(norm_target_ea), "name": norm_target_name},
        "callers": [
            {"ea": int(c_ea), "name": _ea_func_name(c_ea)}
            for c_ea in sorted(callers)
        ],
    }


def get_callers(ea: int | None = None, name: str | None = None,
                include_thunks: bool = True) -> dict[str, Any]:
    """Return unique caller functions for the target function."""
    return _collect_callers(ea=ea, name=name, include_thunks=include_thunks)

# -----------------------------------------------------------------------------

@ida_read
def _collect_callees(ea: int | None, name: str | None,
                     only_direct: bool, include_thunks: bool) -> dict[str, Any]:
    idaapi.auto_wait()

    fn = resolve_func(ea=ea, name=name)
    src_ea = fn.start_ea

    callees: set[int] = set()
    blk = ida_xref.xrefblk_t()
    for item_ea in _iter_func_items(fn):
        if blk.first_from(item_ea, ida_xref.XREF_ALL):
            while True:
                if blk.iscode and _is_call(blk.type):
                    tgt = _normalize_callee_ea(int(blk.to), include_thunks)
                    callees.add(tgt)
                elif not only_direct:
                    pass
                if not blk.next_from():
                    break

    return {
        "source": {"ea": int(src_ea), "name": _ea_func_name(src_ea)},
        "callees": [
            {"ea": int(t_ea), "name": _ea_func_name(t_ea)}
            for t_ea in sorted(callees)
        ],
    }


def get_callees(ea: int | None = None, name: str | None = None,
                only_direct: bool = True, include_thunks: bool = True) -> dict[str, Any]:
    """Return unique callee functions reached from the target function."""
    return _collect_callees(
        ea=ea,
        name=name,
        only_direct=only_direct,
        include_thunks=include_thunks,
    )
