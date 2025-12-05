from typing import Any

# Prefer native PySide6 (IDA 9.2+), fall back to PyQt5 (≤ 9.1 or shims)
try:
    from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore
    QT_BINDING = "PySide6"
except Exception:  # pragma: no cover
    from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore
    QT_BINDING = "PyQt5"


def exec_menu(menu: QtWidgets.QMenu, *args: Any, **kwargs: Any) -> Any:
    """
    Call QMenu.exec/exec_ in a way that works on both PyQt5 & PySide6.
    """
    if hasattr(menu, "exec_"):
        # PyQt5 (and PyQt5 shims)
        return menu.exec_(*args, **kwargs)
    # PySide6
    return menu.exec(*args, **kwargs)
