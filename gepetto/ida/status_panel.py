import datetime
from typing import Optional

import ida_kernwin

# Use PySide6 exclusively (IDA 9.x). Do not mix bindings.
try:
    from PySide6 import QtWidgets, QtCore  # type: ignore
except Exception:
    QtWidgets = None  # Fallback to console-only logging


class GepettoStatusForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        # This follows Hex-Rays' example: FormToPyQtWidget + build layout
        self.parent = None
        if QtWidgets is not None:
            try:
                self.parent = self.FormToPyQtWidget(form)
            except Exception:
                self.parent = None
        self._build_ui()

    def OnClose(self, form):
        pass

    def _build_ui(self):
        if QtWidgets is None or self.parent is None:
            return
        layout = QtWidgets.QVBoxLayout(self.parent)

        # Header: model, status, progress
        header = QtWidgets.QHBoxLayout()
        self._model_label = QtWidgets.QLabel("Model: -")
        self._status_label = QtWidgets.QLabel("Idle")
        self._progress = QtWidgets.QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        header.addWidget(self._model_label)
        header.addStretch(1)
        header.addWidget(self._status_label)
        header.addWidget(self._progress)

        # Log area
        self._log = QtWidgets.QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(5000)

        # Controls
        controls = QtWidgets.QHBoxLayout()
        self._autoscroll = QtWidgets.QCheckBox("Auto-scroll")
        self._autoscroll.setChecked(True)
        self._verbose = QtWidgets.QCheckBox("Verbose")
        self._verbose.setChecked(True)
        btn_clear = QtWidgets.QPushButton("Clear")
        btn_clear.clicked.connect(self._log.clear)
        controls.addWidget(self._autoscroll)
        controls.addWidget(self._verbose)
        controls.addStretch(1)
        controls.addWidget(btn_clear)

        layout.addLayout(header)
        layout.addWidget(self._log)
        layout.addLayout(controls)
        # Mark as ready and request flush of any pending logs/status
        try:
            self.is_ready = True
            if QtCore is not None:
                # Defer flush to next iteration of the event loop
                from gepetto.ida.status_panel import panel  # late import to avoid circular refs
                QtCore.QTimer.singleShot(0, panel._flush_via_exec)
        except Exception:
            pass

    # ------------------------------ API ------------------------------
    def set_model(self, model_name: str):
        if QtWidgets is None or self.parent is None:
            return
        self._model_label.setText(f"Model: {model_name}")

    def set_status(self, text: str, busy: Optional[bool] = None):
        if QtWidgets is None or self.parent is None:
            return
        self._status_label.setText(text)
        if busy is not None:
            self._progress.setVisible(bool(busy))

    def append_log(self, line: str):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"{timestamp} | {line}"
        if QtWidgets is None or self.parent is None:
            # Fallback: print to IDA output
            try:
                print(entry)
            except Exception:
                pass
            return
        # Apply simple verbosity filter: hide noisy tool lines when unchecked
        if hasattr(self, "_verbose") and not self._verbose.isChecked():
            if line.startswith("→ "):
                return
        self._log.appendPlainText(entry)
        if self._autoscroll.isChecked():
            self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())


class _StatusPanelManager:
    def __init__(self):
        self._form: Optional[GepettoStatusForm] = None
        # Fallback for environments that only stub MFF_WRITE
        self._MFF_FAST = getattr(ida_kernwin, "MFF_FAST", getattr(ida_kernwin, "MFF_WRITE", 0))
        # Pending state until UI is ready
        self._pending_model: Optional[str] = None
        self._pending_status: Optional[tuple[str, Optional[bool]]] = None
        self._pending_logs: list[str] = []

    def _is_ready(self) -> bool:
        return bool(self._form and getattr(self._form, "_log", None))

    def _flush_pending_ui(self):
        if not self._is_ready():
            return
        # Apply model
        if self._pending_model is not None:
            try:
                self._form.set_model(self._pending_model)
            except Exception:
                pass
            self._pending_model = None
        # Apply status
        if self._pending_status is not None:
            text, busy = self._pending_status
            try:
                self._form.set_status(text, busy)
            except Exception:
                pass
            self._pending_status = None
        # Apply logs
        if self._pending_logs:
            for line in self._pending_logs:
                try:
                    self._form.append_log(line)
                except Exception:
                    pass
            self._pending_logs.clear()

    def _flush_via_exec(self):
        try:
            ida_kernwin.execute_sync(lambda: (self._flush_pending_ui() or 1), self._MFF_FAST)
        except Exception:
            pass

    def ensure_shown(self):
        # For menu/CLI activation, we're likely on the UI thread. Try direct Show().
        try:
            if self._form is None:
                self._form = GepettoStatusForm()
                # Persist and dock to the right by default
                self._form.Show(
                    "Gepetto Status",
                    options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT),
                )
                # Try docking near Output window if APIs are available
                try:
                    tw = self._form.GetWidget()
                    if hasattr(ida_kernwin, "find_widget") and hasattr(ida_kernwin, "set_dock_pos"):
                        outw = ida_kernwin.find_widget("Output window")
                        if outw is not None:
                            ida_kernwin.set_dock_pos(tw, outw, getattr(ida_kernwin, "DP_RIGHT", 2), 0, 0, 0, 0, True)
                except Exception:
                    pass
                # Request a flush on next loop to apply any pending updates
                if QtCore is not None:
                    QtCore.QTimer.singleShot(0, self._flush_via_exec)
                return
        except Exception:
            pass
        # Fall back to execute_sync; ensure inner errors are swallowed
        def _do():
            try:
                if self._form is None:
                    self._form = GepettoStatusForm()
                    self._form.Show(
                        "Gepetto Status",
                        options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT),
                    )
                    # Try docking via APIs
                    try:
                        tw = self._form.GetWidget()
                        if hasattr(ida_kernwin, "find_widget") and hasattr(ida_kernwin, "set_dock_pos"):
                            outw = ida_kernwin.find_widget("Output window")
                            if outw is not None:
                                ida_kernwin.set_dock_pos(tw, outw, getattr(ida_kernwin, "DP_RIGHT", 2), 0, 0, 0, 0, True)
                    except Exception:
                        pass
                    if QtCore is not None:
                        QtCore.QTimer.singleShot(0, self._flush_via_exec)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
        except Exception:
            # Last-resort fallback to simple print
            try:
                print("Could not show Gepetto Status panel.")
            except Exception:
                pass

    # -------------------------- convenience wrappers -------------------------
    def set_model(self, name: str):
        self._pending_model = name
        if not self._is_ready():
            return
        self._flush_via_exec()

    def set_status(self, text: str, busy: Optional[bool] = None):
        self._pending_status = (text, busy)
        if not self._is_ready():
            return
        self._flush_via_exec()

    def log(self, line: str):
        # If panel not ready, store & print to console as a fallback
        if not self._is_ready():
            self._pending_logs.append(line)
            try:
                timestamped = f"{datetime.datetime.now().strftime('%H:%M:%S')} | {line}"
                print(timestamped)
            except Exception:
                pass
            return
        def _do():
            try:
                self._form.append_log(line)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
        except Exception:
            pass


# Singleton instance
panel = _StatusPanelManager()
