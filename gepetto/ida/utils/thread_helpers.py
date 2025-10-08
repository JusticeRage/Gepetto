"""
Thread-safety helpers for interacting with IDA APIs.

These utilities wrap ``execute_sync`` and related primitives so callers can
schedule database mutations on the main thread without littering defensive
boilerplate throughout the codebase.  The goal is to operate correctly on
IDA 7.x (PyQt5) while remaining tolerant of headless or partially initialised
environments, which is important when unit tests import modules outside IDA.
"""

from __future__ import annotations

from typing import Any, Callable, Optional
import importlib


def _safe_import(module_name: str) -> Optional[Any]:
    """Gracefully import a module, returning None if it's not found."""
    try:
        return importlib.import_module(module_name)
    except ImportError:  # pragma: no cover - executed outside IDA.
        return None

# Gracefully import IDA modules, setting them to None if unavailable
# (e.g., when running unit tests outside of an IDA environment).
idaapi = _safe_import("idaapi")
ida_kernwin = _safe_import("ida_kernwin")
ida_hexrays = _safe_import("ida_hexrays")
ida_funcs = _safe_import("ida_funcs")
idc = _safe_import("idc")


# Sentinel BADADDR for environments without idaapi.
BADADDR = getattr(idaapi, "BADADDR", -1)


def _is_main_thread() -> bool:
    """Return True if the current thread is the IDA main/UI thread."""
    fn = getattr(ida_kernwin, "is_main_thread", None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception:
            return False
    return False


def _execute_sync(callable_: Callable[[], Any], write: bool) -> Any:
    """
    Execute ``callable_`` on IDA's main thread and return its result.

    The helper captures exceptions raised by ``callable_`` and re-raises them
    on the caller's thread so upstream code can handle failures consistently.
    """
    if ida_kernwin is None and idaapi is None:
        return callable_()

    flag = None
    if ida_kernwin is not None:
        flag = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
        exec_fn = getattr(ida_kernwin, "execute_sync", None)
    else:
        exec_fn = getattr(idaapi, "execute_sync", None)
        if idaapi is not None:
            flag = idaapi.MFF_WRITE if write else idaapi.MFF_READ

    if callable(exec_fn):
        slot: dict[str, Any] = {}

        def runner() -> int:
            try:
                slot["result"] = callable_()
                slot["ok"] = True
            except Exception as exc:  # pragma: no cover - IDA specific.
                slot["error"] = exc
                slot["ok"] = False
            return 1

        exec_fn(runner, flag)
        if not slot.get("ok", False):
            error = slot.get("error")
            if isinstance(error, Exception):
                raise error
            raise RuntimeError("Failed to execute on IDA main thread")
        return slot.get("result")

    # execute_sync unavailable (e.g., unit tests): run inline.
    return callable_()


def run_on_main_thread(func: Callable[[], Any], write: bool = False) -> Any:
    """
    Execute ``func`` on the IDA main thread if necessary.

    Args:
        func: Callable to execute.
        write: Whether the callable mutates the database (selects MFF_WRITE).

    Returns:
        The return value of ``func``.
    """
    if _is_main_thread():
        return func()
    return _execute_sync(func, write=write)


def safe_get_screen_ea() -> int:
    """
    Fetch the current screen EA while tolerating headless execution.

    Returns:
        Current EA or BADADDR if unavailable.
    """
    if ida_kernwin is not None:
        try:
            ea = run_on_main_thread(lambda: ida_kernwin.get_screen_ea(), write=False)
            if isinstance(ea, int) and ea != BADADDR:
                return int(ea)
        except Exception:
            pass

    if idc is not None:
        try:
            ea = idc.get_screen_ea()
            if isinstance(ea, int) and ea != BADADDR:
                return int(ea)
        except Exception:
            pass

    return BADADDR


def hexrays_available() -> bool:
    """Return True if Hex-Rays is available and initialised."""
    try:
        return bool(ida_hexrays and ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def decompile_func(func_ea: int):
    """
    Safely decompile the function containing ``func_ea``.

    Raises:
        RuntimeError if Hex-Rays is unavailable or decompilation fails.
    """
    if not isinstance(func_ea, int) or func_ea == BADADDR:
        raise RuntimeError("Invalid function address for decompilation")
    if not hexrays_available():
        raise RuntimeError("Hex-Rays not available: install or enable the decompiler.")

    def _do():
        func = ida_funcs.get_func(func_ea) if ida_funcs is not None else None
        if func is not None:
            return ida_hexrays.decompile(func)
        # Fallback: try direct decompile for raw EA.
        return ida_hexrays.decompile(func_ea)

    cfunc = run_on_main_thread(_do, write=False)
    if cfunc is None:
        raise RuntimeError(f"Hex-Rays failed to decompile function at {func_ea:#x}")
    return cfunc


__all__ = [
    "BADADDR",
    "decompile_func",
    "hexrays_available",
    "run_on_main_thread",
    "safe_get_screen_ea",
]
