from __future__ import annotations

from collections.abc import Callable
import ida_kernwin

_desktop_ready = False
_desktop_hook: _DesktopHooks | None = None
_pending: list[Callable[[], None]] = []

class _DesktopHooks(ida_kernwin.UI_Hooks):
    def desktop_applied(self, name, from_idb, layout_type):  # noqa: ANN001
        _mark_desktop_ready()
        return 0

def _mark_desktop_ready() -> None:
    global _desktop_ready, _desktop_hook
    _desktop_ready = True
    if _desktop_hook is not None:
        try:
            _desktop_hook.unhook()
        except Exception:
            pass
        _desktop_hook = None
    _flush_pending()

def _flush_pending() -> None:
    while _pending:
        callback = _pending.pop(0)
        try:
            callback()
        except Exception:
            pass

def _ensure_desktop_hook() -> None:
    global _desktop_hook
    if _desktop_ready:
        return
    if _desktop_hook is None:
        hook = _DesktopHooks()
        try:
            hook.hook()
            _desktop_hook = hook
        except Exception:
            _desktop_hook = None
            _mark_desktop_ready()

def _guess_desktop_ready() -> bool:
    try:
        return bool(ida_kernwin.find_widget("IDA View-A"))
    except Exception:
        return False

def run_when_desktop_ready(callback: Callable[[], None]) -> None:
    if _desktop_ready or _guess_desktop_ready():
        _mark_desktop_ready()
        callback()
        return
    _pending.append(callback)
    _ensure_desktop_hook()
