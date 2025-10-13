"""
Thread-safety helpers for interacting with IDA APIs.

These utilities wrap ``execute_sync`` and related primitives so callers can
schedule database mutations on the main thread without littering defensive
boilerplate throughout the codebase.  The goal is to operate correctly on
IDA 7.x (PyQt5) while remaining tolerant of headless or partially initialised
environments, which is important when unit tests import modules outside IDA.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import idaapi  # type: ignore
import ida_kernwin  # type: ignore
import ida_hexrays  # type: ignore
import idc  # type: ignore

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


def sync_on_main_thread(write: bool = False):
    """Decorator factory that executes the wrapped callable on IDA's main thread."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return run_on_main_thread(lambda: func(*args, **kwargs), write=write)

        return wrapper

    return decorator


def ida_read(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator enforcing main-thread execution with a read lock."""

    return sync_on_main_thread(write=False)(func)


def ida_write(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator enforcing main-thread execution with a write lock."""

    return sync_on_main_thread(write=True)(func)


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
    if ida_hexrays is None:
        return False

    def _init() -> bool:
        try:
            return bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            return False

    try:
        return bool(run_on_main_thread(_init, write=False))
    except Exception:
        return False


__all__ = [
    "BADADDR",
    "hexrays_available",
    "ida_read",
    "ida_write",
    "run_on_main_thread",
    "safe_get_screen_ea",
    "sync_on_main_thread",
]
