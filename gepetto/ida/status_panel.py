"""Qt5 status panel mirroring the original Gepetto UI layout."""

from __future__ import annotations

import datetime
from typing import Callable, Optional

import ida_kernwin

import gepetto.config

_ = gepetto.config._

_DEFAULT_DOCK_OPTIONS = (
    getattr(ida_kernwin.PluginForm, "WOPN_PERSIST", 0)
    | getattr(ida_kernwin.PluginForm, "WOPN_RESTORE", 0)
)

try:  # Prefer PyQt5 on IDA 7.x; fall back to PySide6 for newer builds.
    from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore
except ImportError:  # pragma: no cover - executed on IDA >= 9.2 with PySide6
    try:
        from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore
    except ImportError:  # pragma: no cover - headless testing environment
        QtCore = QtGui = QtWidgets = None  # type: ignore


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


class GepettoStatusForm(ida_kernwin.PluginForm):
    """Dockable widget that displays the streaming answer and log."""

    def __init__(self, owner: "_StatusPanelManager") -> None:
        super().__init__()
        self._owner = owner
        self._widget: Optional[QtWidgets.QWidget] = None if QtWidgets else None
        self._log: Optional[QtWidgets.QTextEdit] = None
        self._model_label: Optional[QtWidgets.QLabel] = None
        self._status_label: Optional[QtWidgets.QLabel] = None
        self._stop_button: Optional[QtWidgets.QPushButton] = None
        self._clear_button: Optional[QtWidgets.QPushButton] = None
        self._stream_active = False
        self._stream_text: list[str] = []
        self._ready = False

    # ------------------------------------------------------------------
    def OnCreate(self, form):  # noqa: N802 - IDA callback signature
        if QtWidgets is None:
            return
        self._widget = ida_kernwin.PluginForm.FormToPyQtWidget(form)
        self._build_ui()
        self._ready = True
        self._owner.on_form_ready()

    # ------------------------------------------------------------------
    def OnClose(self, form):  # noqa: N802 - IDA callback signature
        del form
        self._widget = None
        self._log = None
        self._model_label = None
        self._status_label = None
        self._stop_button = None
        self._clear_button = None
        self._stream_active = False
        self._stream_text = []
        self._ready = False
        self._owner.form_closed()

    # ------------------------------------------------------------------
    def is_ready(self) -> bool:
        return bool(self._widget and self._ready)

    # ------------------------------------------------------------------
    def widget(self):  # noqa: ANN001 - helper used by the manager
        return self._widget

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        if QtWidgets is None or self._widget is None:
            return

        layout = QtWidgets.QVBoxLayout(self._widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        top_row = QtWidgets.QHBoxLayout()
        top_row.addStretch(1)
        self._clear_button = QtWidgets.QPushButton(_("Clear"))
        self._clear_button.clicked.connect(self._owner.clear_log)  # type: ignore[arg-type]
        top_row.addWidget(self._clear_button)
        layout.addLayout(top_row)

        self._log = QtWidgets.QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(160)
        try:
            self._log.document().setMaximumBlockCount(2000)
        except Exception:
            pass
        layout.addWidget(self._log, stretch=1)

        bottom_row = QtWidgets.QHBoxLayout()
        self._model_label = QtWidgets.QLabel(_("Model: {model}").format(model=str(gepetto.config.model)))
        bottom_row.addWidget(self._model_label)
        bottom_row.addStretch(1)
        self._status_label = QtWidgets.QLabel(_("Status: {status}").format(status=_("Idle")))
        bottom_row.addWidget(self._status_label)

        self._stop_button = QtWidgets.QPushButton(_("Stop"))
        self._stop_button.setVisible(True)
        self._stop_button.setEnabled(False)
        self._stop_button.clicked.connect(self._owner.request_stop)  # type: ignore[arg-type]
        bottom_row.addWidget(self._stop_button)

        layout.addLayout(bottom_row)

    # ------------------------------------------------------------------

    def _force_cursor_to_end(self):
        if QtGui is None or self._log is None:
            return
        self._log.moveCursor(QtGui.QTextCursor.End)

    def _ensure_newline(self, *, require_existing_text: bool) -> None:
        if QtGui is None or self._log is None:
            return
        try:
            doc_text = self._log.toPlainText()
        except Exception:
            return
        if require_existing_text and not doc_text:
            return
        if doc_text.endswith("\n"):
            return
        self._force_cursor_to_end()
        try:
            self._log.insertPlainText("\n")
        except Exception:
            pass

    # ------------------------------------------------------------------
    def set_model(self, model_name: str) -> None:
        if self._model_label:
            self._model_label.setText(_("Model: {model}").format(model=model_name))

    # ------------------------------------------------------------------
    def set_status(self, text: str, *, busy: bool = False, error: bool = False) -> None:
        if self._status_label is None:
            return
        status_text = text or _("Idle")
        self._status_label.setText(_("Status: {status}").format(status=status_text))
        if QtGui is None:
            return
        palette = self._status_label.palette()
        if error:
            palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#c92a2a"))
        elif busy:
            palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#e67700"))
        else:
            palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#2f9e44"))
        self._status_label.setPalette(palette)

    # ------------------------------------------------------------------
    def reset_stop(self) -> None:
        if self._stop_button is None:
            return
        self._stop_button.setText(_("Stop"))
        self._stop_button.setEnabled(self._owner.has_stop_callback())

    # ------------------------------------------------------------------
    def set_stop_callback(self, callback: Optional[Callable[[], None]]) -> None:
        if self._stop_button is None:
            return
        self._stop_button.setEnabled(callback is not None)

    # ------------------------------------------------------------------
    def mark_error(self, message: str) -> None:
        self.set_status(message, error=True)
        if self._stop_button:
            self._stop_button.setEnabled(False)

    # ------------------------------------------------------------------
    def clear_log(self) -> None:
        if self._log:
            self._log.clear()

    # ------------------------------------------------------------------
    def append_log(self, message: str, newline: bool = False) -> None:
        if not self._log:
            return
        entry = f"{_timestamp()} : {message}"
        self._ensure_newline(require_existing_text=True)
        self._force_cursor_to_end()
        self._log.insertPlainText(entry)
        if newline:
            self._ensure_newline(require_existing_text=False)
        if QtWidgets:
            self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    # ------------------------------------------------------------------
    def log_user(self, text: str) -> None:
        self.append_log(f"[{_('You')}] {text}")

    # ------------------------------------------------------------------
    def log_assistant(self, text: str) -> None:
        self.append_log(f"[{_('Gepetto')}] {text}")

    # ------------------------------------------------------------------
    def start_stream(self) -> None:
        model_name = str(gepetto.config.model)
        self.set_model(model_name)
        if not self._log or QtGui is None:
            return
        header = f"[{_('Gepetto')} ({model_name})] " if model_name is not None else f"[{_('Gepetto')}]"
        self._stream_text = []
        self._stream_active = True
        self.append_log(header)

    # ------------------------------------------------------------------
    def append_stream(self, chunk: str) -> None:
        if not self._stream_active or not chunk or not self._log or QtGui is None:
            return
        self._stream_text.append(chunk)
        self._force_cursor_to_end()
        self._log.insertPlainText(chunk)

    # ------------------------------------------------------------------
    def finish_stream(self, final_text: str) -> None:
        finished_message = "".join(self._stream_text)
        self._stream_text = []
        self._stream_active = False
        if not self._log or QtGui is None:
            return
        if final_text != finished_message:
            self.log_assistant(final_text)
        self._ensure_newline(require_existing_text=False)


class _StatusPanelManager:
    """Controller keeping a singleton instance of the status panel."""

    def __init__(self) -> None:
        self._form: Optional[GepettoStatusForm] = None
        self._stop_callback: Optional[Callable[[], None]] = None
        self._docked = False

    # ------------------------------------------------------------------
    def ensure_shown(self) -> None:
        if self._form is None:
            self._form = GepettoStatusForm(self)
            try:
                self._form.Show(_("Gepetto Status"), options=_DEFAULT_DOCK_OPTIONS)
            except Exception:
                print(_("Could not show Gepetto Status panel."))
                return
        try:
            ida_kernwin.activate_widget(_("Gepetto Status"), True)
            self._dock()
        except Exception:
            pass

    # ------------------------------------------------------------------
    def form_closed(self) -> None:
        self._form = None
        self._docked = False

    # ------------------------------------------------------------------
    def on_form_ready(self) -> None:
        self._dock()
        self.set_model(str(gepetto.config.model))
        if self._stop_callback:
            self._form.set_stop_callback(self._stop_callback)  # type: ignore[union-attr]
            self._form.reset_stop()  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    def _dock(self) -> None:
        if self._form is None or not self._form.is_ready() or self._docked:
            return
        if self._form._widget and ida_kernwin.find_widget("IDA View-A"):
            if ida_kernwin.set_dock_pos(_("Gepetto Status"), "IDA View-A", ida_kernwin.DP_RIGHT):
                self._docked = True

    # ------------------------------------------------------------------
    def set_model(self, model_name: str) -> None:
        self._dispatch(lambda form: form.set_model(model_name))

    # ------------------------------------------------------------------
    def set_status(self, text: str, *, busy: bool = False, error: bool = False) -> None:
        self._dispatch(lambda form: form.set_status(text, busy=busy, error=error))

    # ------------------------------------------------------------------
    def reset_stop(self) -> None:
        self._dispatch(lambda form: form.reset_stop())

    # ------------------------------------------------------------------
    def set_stop_callback(self, callback: Optional[Callable[[], None]]) -> None:
        self._stop_callback = callback

        def apply(form: GepettoStatusForm) -> None:
            form.set_stop_callback(callback)

        self._dispatch(apply)
        self.reset_stop()

    # ------------------------------------------------------------------
    def has_stop_callback(self) -> bool:
        return self._stop_callback is not None

    # ------------------------------------------------------------------
    def request_stop(self) -> None:
        if self._stop_callback:
            try:
                self._stop_callback()
            except Exception:
                pass
            finally:
                self.set_status(_("Idle"))
                self.reset_stop()

    # ------------------------------------------------------------------
    def start_stream(self) -> None:
        self._dispatch(lambda form: form.start_stream())

    # ------------------------------------------------------------------
    def append_stream(self, chunk: str) -> None:
        self._dispatch(lambda form: form.append_stream(chunk))

    # ------------------------------------------------------------------
    def finish_stream(self, final_text: str) -> None:
        self._dispatch(lambda form: form.finish_stream(final_text))

    # ------------------------------------------------------------------
    def log_user(self, text: str) -> None:
        self._dispatch(lambda form: form.log_user(text))

    # ------------------------------------------------------------------
    def log(self, message: str) -> None:
        self._dispatch(lambda form: form.append_log(message, True))

    # ------------------------------------------------------------------
    def log_request_started(self) -> str:
        message = _("Request to {model} sent...").format(model=str(gepetto.config.model))
        self.log(message)
        return message

    # ------------------------------------------------------------------
    def log_request_finished(self, elapsed_seconds: float) -> str:
        message = _("{model} query finished in {time:.2f} seconds!").format(
            model=str(gepetto.config.model),
            time=elapsed_seconds,
        )
        self.log(message)
        return message

    # ------------------------------------------------------------------
    def mark_error(self, message: str) -> None:
        self._dispatch(lambda form: form.mark_error(message))

    # ------------------------------------------------------------------
    def clear_log(self) -> None:
        self._dispatch(lambda form: form.clear_log())

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._form and self._form.is_ready():
            try:
                ida_kernwin.close_widget(self._form.widget(), 0)
            except Exception:
                pass
        self._form = None
        self._stop_callback = None
        self._docked = False

    # ------------------------------------------------------------------

    def _dispatch(self, action: Callable[[GepettoStatusForm], None]) -> None:
        if self._form is None:
            return

        def runner() -> None:
            form = self._form
            if not form or not form.is_ready():
                return
            try:
                action(form)
            except Exception:
                pass

        if QtCore is None:
            runner()
            return

        widget = self._form.widget()
        if widget:
            current_thread = QtCore.QThread.currentThread()
            widget_thread = widget.thread()
            if widget_thread == current_thread:
                runner()
                return

        try:
            ida_kernwin.execute_sync(runner, ida_kernwin.MFF_FAST)
        except Exception:
            runner()


panel = _StatusPanelManager()


def get_status_panel() -> _StatusPanelManager:
    return panel
