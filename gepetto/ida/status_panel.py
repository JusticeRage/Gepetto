import datetime
from typing import Optional

import ida_kernwin
import gepetto.config

# Use PySide6 exclusively (IDA 9.x). Do not mix bindings.
try:
    from PySide6 import QtWidgets, QtCore, QtGui  # type: ignore
except Exception:
    QtWidgets = QtCore = QtGui = None  # Fallback to console-only logging


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
        self._model_label = QtWidgets.QLabel(f"Model: {gepetto.config.get_config('Gepetto', 'MODEL')}")
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
        # Streaming state
        self._stream_active = False
        self._stream_prefix = ""

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
        entry = f"{timestamp} | {line}\n"
        if QtWidgets is None or self.parent is None or QtGui is None:
            # Fallback: print to IDA output
            try:
                print(entry, end="")
            except Exception:
                pass
            return
        # Apply simple verbosity filter: hide noisy tool lines when unchecked
        if hasattr(self, "_verbose") and not self._verbose.isChecked():
            if line.startswith("→ "):
                return
        
        # Use the robust moveCursor/insertPlainText logic
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        self._log.insertPlainText(entry)

        if self._autoscroll.isChecked():
            self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    # Stream text into the log without creating new lines per chunk.
    # Starts a new timestamped row with the given prefix on first call,
    # then appends subsequent text to the same row.
    def append_stream(self, text: str, prefix: str = "Gepetto: "):
        if QtWidgets is None or self.parent is None or QtGui is None:
            print("ERROR")
            # Console fallback handled by manager
            return
        # Apply verbosity filter: hide tool streaming when unchecked
        if hasattr(self, "_verbose") and not self._verbose.isChecked():
            if str(prefix).startswith("→ "):
                return

        # Move cursor to the very end of the document
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)

        # Initialize the stream line if needed
        if not self._stream_active:
            self._stream_active = True
            self._stream_prefix = prefix
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            header = f"{timestamp} | {prefix}"
            self._log.insertPlainText(header)

        # Now, insert the new text at the cursor's current position
        self._log.insertPlainText(text)

        if self._autoscroll.isChecked():
            self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def end_stream(self):
        if QtWidgets is None or self.parent is None or QtGui is None:
            return
        if not getattr(self, "_stream_active", False):
            return
        # Finish the line with a newline and reset state
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        self._log.insertPlainText("\n")
        self._stream_active = False
        self._stream_prefix = ""


class _StatusPanelManager:
    def __init__(self):
        self._form: Optional[GepettoStatusForm] = None
        # Fallback for environments that only stub MFF_WRITE
        self._MFF_FAST = getattr(ida_kernwin, "MFF_FAST", getattr(ida_kernwin, "MFF_WRITE", 0))
        # Pending state until UI is ready
        self._pending_model: Optional[str] = None
        self._pending_status: Optional[tuple[str, Optional[bool]]] = None
        self._pending_logs: list[str] = []
        # Pending streaming state
        self._pending_stream_prefix: Optional[str] = None
        self._pending_stream_text: list[str] = []
        self._fallback_stream_active = False
        # New state for stream batching
        self._stream_buffer: list[str] = []
        self._stream_prefix_for_batch: Optional[str] = None
        self._last_flush_time = 0

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
        # Apply any pending stream text (keeps it on the same line)
        if self._pending_stream_text:
            try:
                prefix = self._pending_stream_prefix or "Gepetto: "
                self._form.append_stream("".join(self._pending_stream_text), prefix)
            except Exception:
                pass
            # Clear pending stream buffer after flush
            self._pending_stream_text.clear()
            self._pending_stream_prefix = None

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

    def _flush_stream_buffer(self):
        if not self._stream_buffer:
            return

        text_to_flush = "".join(self._stream_buffer)
        prefix = self._stream_prefix_for_batch

        self._stream_buffer.clear()

        def _do():
            try:
                self._form.append_stream(text_to_flush, prefix)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
        except Exception:
            pass

    def log_stream(self, text: str, prefix: str = "Gepetto: "):
        # If panel not ready, buffer and print to console without newlines
        if not self._is_ready():
            self._pending_stream_prefix = prefix
            self._pending_stream_text.append(text)
            try:
                if not self._fallback_stream_active:
                    ts = datetime.datetime.now().strftime('%H:%M:%S')
                    print(f"{ts} | {prefix}", end="", flush=True)
                    self._fallback_stream_active = True
                print(text, end="", flush=True)
            except Exception:
                pass
            return

        if not self._stream_buffer:
            self._stream_prefix_for_batch = prefix
        self._stream_buffer.append(text)

        # Heuristics: flush on whitespace, punctuation, or if the buffer grows large.
        punct = {" ", "\n", "\t", ".", ",", ";", ":", "!", "?", ")", "]", "}"}
        last = text[-1:] if text else ""
        if any(ch in text for ch in punct) or last in punct or len("".join(self._stream_buffer)) >= 160:
            self._flush_stream_buffer()

    def end_stream(self):
        # Flush any remaining stream buffer
        self._flush_stream_buffer()

        # Finish the current streaming line
        if not self._is_ready():
            # Convert any pending stream to a single queued log line
            try:
                if self._pending_stream_text:
                    combined = f"{self._pending_stream_prefix or ''}{''.join(self._pending_stream_text)}"
                    self._pending_logs.append(combined)
                if self._fallback_stream_active:
                    print()
            except Exception:
                pass
            # Reset pending stream state
            self._pending_stream_text.clear()
            self._pending_stream_prefix = None
            self._fallback_stream_active = False
            return
        def _do():
            try:
                self._form.end_stream()
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
        except Exception:
            pass


# Singleton instance
panel = _StatusPanelManager()
