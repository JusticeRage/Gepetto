"""Binding layouts differ even when PyQt5 is a shim over Qt6."""
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("name,version,location", [
    ("PySide6", 6, "gui"),
    ("PyQt5", 5, "widgets"),
    ("PyQt5", 5, "gui"),
])
def test_shortcut_uses_available_module(monkeypatch, name, version, location):
    import idaapi
    monkeypatch.setattr(idaapi, "is_idaq", lambda: False)
    qt = runpy.run_path(str(Path(__file__).parents[1] / "gepetto/ida/qt.py"))
    shortcut = type("Shortcut", (), {})
    dialog = type("Dialog", (), {"exec_": lambda self: None})
    core = SimpleNamespace(Qt=SimpleNamespace(TextSelectableByMouse=1,
                                              TextSelectableByKeyboard=2))
    gui = SimpleNamespace()
    widgets = SimpleNamespace(QDialog=dialog, QMessageBox=dialog, QMenu=dialog)
    setattr(gui if location == "gui" else widgets, "QShortcut", shortcut)
    adopt = qt["_adopt"]
    adopt(name, version, core, gui, widgets)
    assert adopt.__globals__["QShortcut"] is shortcut
