"""
Qt compatibility shim for IDA < 9.2 (Qt5/PyQt5) while keeping
PySide6/Qt6 code paths intact on IDA 9.2+.

Usage:
    from gepetto import qt_compat
    qt_compat.install()

This populates sys.modules entries for "PySide6" when only PyQt5 (Qt5)
is available in older IDA builds, so existing imports like:
    from PySide6 import QtWidgets, QtCore, QtGui
continue to work without touching the rest of the codebase.

Notes:
- On IDA 9.2+ (PySide6 present), this is a no-op.
- On older IDA with PyQt5, this aliases PySide6.* → PyQt5.*.
- If shiboken2 is available, it is also aliased to shiboken6 for callers
  that might import it (this plugin doesn’t rely on it directly).
"""

from __future__ import annotations

import importlib
import sys
import types
from typing import Optional


def _try_import(name: str):
    try:
        return importlib.import_module(name)
    except Exception:
        return None


def _alias_module(name: str, module):
    sys.modules[name] = module
    return module


def _ensure_submodule(parent_name: str, attr: str, module):
    # Register both as attribute on parent package, and as a proper module
    parent = sys.modules.get(parent_name)
    if parent is None:
        parent = types.ModuleType(parent_name)
        sys.modules[parent_name] = parent
    setattr(parent, attr, module)
    sys.modules[f"{parent_name}.{attr}"] = module


def install() -> None:
    """Install a runtime alias so PySide6 imports succeed on PyQt5 installs.

    - If PySide6 already imports, do nothing.
    - Else, try PyQt5 (Qt5) and alias the submodules that our plugin uses.
    - As a best-effort, also alias shiboken2 → shiboken6 if present.
    """
    # Fast-path: PySide6 available → no-op
    if _try_import("PySide6") is not None:
        return

    # Try PyQt5 (IDA < 9.2 ships PyQt5/Qt5)
    qtcore = _try_import("PyQt5.QtCore")
    qtgui = _try_import("PyQt5.QtGui")
    qtwidgets = _try_import("PyQt5.QtWidgets")

    if not (qtcore and qtgui and qtwidgets):
        # Optional: try PySide2 as an additional fallback, though IDA usually ships PyQt5
        ps2_core = _try_import("PySide2.QtCore")
        ps2_gui = _try_import("PySide2.QtGui")
        ps2_widgets = _try_import("PySide2.QtWidgets")
        if ps2_core and ps2_gui and ps2_widgets:
            qtcore, qtgui, qtwidgets = ps2_core, ps2_gui, ps2_widgets
        else:
            # Nothing we can do; leave things as-is so callers can gracefully degrade
            return

    # Create a synthetic top-level package for PySide6
    pyside6_pkg = types.ModuleType("PySide6")
    _alias_module("PySide6", pyside6_pkg)

    # Expose the expected submodules
    _ensure_submodule("PySide6", "QtCore", qtcore)
    _ensure_submodule("PySide6", "QtGui", qtgui)
    _ensure_submodule("PySide6", "QtWidgets", qtwidgets)

    # Optional conveniences (only if present)
    qtuitools = _try_import("PyQt5.uic") or _try_import("PySide2.QtUiTools")
    if qtuitools is not None:
        _ensure_submodule("PySide6", "QtUiTools", qtuitools)

    # Best-effort alias for shiboken; some ecosystems expect shiboken6
    sh2 = _try_import("shiboken2")
    if sh2 is not None and "shiboken6" not in sys.modules:
        _alias_module("shiboken6", sh2)

    # Minimal enum backfills for Qt5 environments, only if missing in Qt5
    # (Most usages in this plugin are already compatible.)
    try:
        # Ensure QTextCursor.MoveOperation exists (PyQt5 already provides it).
        # Keep this block small and defensive to avoid changing behavior on Qt6.
        _ = qtgui.QTextCursor.MoveOperation  # type: ignore[attr-defined]
    except Exception:
        try:
            # Create a MoveOperation container with basic members we use.
            class _MoveOperation:
                End = qtgui.QTextCursor.End  # type: ignore[attr-defined]
                StartOfBlock = qtgui.QTextCursor.StartOfBlock  # type: ignore[attr-defined]

            qtgui.QTextCursor.MoveOperation = _MoveOperation  # type: ignore[attr-defined]
        except Exception:
            pass


# Best-effort auto-install when imported very early, but keep explicit install()
# in the plugin entrypoint to guarantee ordering.
try:
    install()
except Exception:
    # Never raise from the shim; silently no-op on errors.
    pass

