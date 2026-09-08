"""Gepetto's view of whichever Qt binding this IDA embeds.

Qt is imported only when `idaapi.is_idaq()` says IDA is the GUI, because
`import PySide6` succeeding proves nothing on its own -- headless IDA, idalib
and a test runner can all have the wheel on the path with no QApplication
behind it, and a widget built there is a crash rather than a dialog.

What is here is the part that is about IDA rather than about Qt: finding a
window to parent a dialog to, and reading an enum whose scoping changed
between Qt5 and Qt6.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Named here only so a type checker has modules to resolve names like
    # QtWidgets.QWidget against, in annotations and in base classes. Nothing
    # imports PySide6 at runtime on this path: which binding is used, and
    # whether one is used at all, is decided below.
    from PySide6 import QtCore, QtGui, QtWidgets
else:
    QtCore = None
    QtGui = None
    QtWidgets = None

binding = None
QT_VERSION = None
QT5 = False
QT6 = False
TEXT_SELECTABLE = None
QShortcut: Any = None


def flag_or(*flags):
    """Qt flags combined, whether they are enums or plain ints."""
    if not flags:
        return 0
    combined = 0
    for flag in flags:
        combined |= flag.value if hasattr(flag, "value") else int(flag)
    try:
        return type(flags[0])(combined)
    except (TypeError, ValueError):
        return combined


def enum_value(owner, scope, name):
    """A Qt enum member, whether or not the binding scopes it.

    Qt6 puts it under its enum type; Qt5 hangs it directly off the class.
    Asking for the scoped one first keeps this right on a binding that has
    dropped the flat aliases PySide6 still carries.
    """
    scoped = getattr(owner, scope, None)
    if scoped is not None and hasattr(scoped, name):
        return getattr(scoped, name)
    return getattr(owner, name)


def _ida_is_the_gui():
    """True only inside IDA's GUI, where Qt exists and has an application."""
    try:
        import idaapi
    except ImportError:
        return False
    try:
        return bool(idaapi.is_idaq())
    except Exception:
        return False


def _import_binding():
    """(name, version, QtCore, QtGui, QtWidgets), or None if neither is there.

    The three modules, deliberately, rather than the individual classes:
    one name a binding does not have takes the whole import down with it, and
    a module always has the classes this actually touches. Measured, not
    guessed: IDA 9.x ships PyQt5 as a shim over PySide6, and that shim has no
    QtWidgets.QShortcut, because Qt6 moved it to QtGui.
    """
    try:
        from PySide6 import QtCore, QtGui, QtWidgets

        return "PySide6", 6, QtCore, QtGui, QtWidgets
    except ImportError:
        try:
            from PyQt5 import QtCore, QtGui, QtWidgets

            return "PyQt5", 5, QtCore, QtGui, QtWidgets
        except ImportError:
            return None


def _adopt(name, version, core, gui, widgets):
    global QtCore, QtGui, QtWidgets, binding, QT_VERSION, QT5, QT6, TEXT_SELECTABLE
    global QShortcut
    QtCore, QtGui, QtWidgets = core, gui, widgets
    # Qt5 uses QtWidgets; Qt6 (including IDA's PyQt5 shim) uses QtGui.
    QShortcut = getattr(gui, "QShortcut", None)
    if QShortcut is None:
        QShortcut = widgets.QShortcut
    binding, QT_VERSION = name, version
    QT5, QT6 = version == 5, version == 6

    selectable = ("TextInteractionFlag", "TextSelectableByMouse",
                  "TextSelectableByKeyboard")
    by_mouse = enum_value(QtCore.Qt, selectable[0], selectable[1])
    by_keyboard = enum_value(QtCore.Qt, selectable[0], selectable[2])
    TEXT_SELECTABLE = flag_or(by_mouse, by_keyboard)

    # Qt6 renamed exec_ to exec. Callers say exec_ and get the same dialog
    # from either binding.
    for widget in (widgets.QDialog, widgets.QMessageBox, widgets.QMenu):
        if not hasattr(widget, "exec_"):
            widget.exec_ = widget.exec


# Qt is imported only once IDA says it is the GUI. `import PySide6` succeeding
# proves nothing on its own: headless IDA, idalib and a test runner can all
# have the wheel on the path with no QApplication behind it, and a widget built
# there is a crash rather than a dialog.
if _ida_is_the_gui():
    _found = _import_binding()
    if _found is None:
        print("Gepetto: no Qt binding found; dialogs will use IDA's forms.")
    else:
        _adopt(*_found)


def available():
    return binding is not None


def main_window():
    """A window to parent a dialog to, or None.

    IDA hands its widgets out as TWidget pointers and owns the conversion to
    Qt, so ask it: doing the wrapping here would mean choosing sip or shiboken
    by hand and being wrong on the other binding. IDA's main window has no
    objectName, so looking for one by name finds nothing.

    A dialog with no parent still opens, but it can end up behind IDA with no
    way to reach it, which looks exactly like the plugin having hung.
    """
    if not available():
        return None

    try:
        import ida_kernwin

        widget = ida_kernwin.get_current_widget()
        if widget is not None:
            converted = ida_kernwin.PluginForm.TWidgetToPyQtWidget(widget)
            if converted is not None:
                return converted.window()
    except Exception:
        pass

    try:
        app = QtWidgets.QApplication.instance()
        if app is None:
            return None
        active = app.activeWindow()
        if active is not None:
            return active
        # activeWindow is None while a popup or context menu holds focus.
        for widget in app.topLevelWidgets() or []:
            if widget is not None and widget.isVisible():
                return widget
    except Exception:
        pass
    return None
