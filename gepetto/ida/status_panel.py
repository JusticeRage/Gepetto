import datetime
from typing import Optional

import ida_kernwin
import gepetto.config

_ = gepetto.config._

def _debug_log(msg):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
    print(f"[Gepetto Debug] {timestamp}: {msg}")

# Use PyQt5 for IDA 7.6+ compatibility.
try:
    from PyQt5 import QtWidgets, QtCore, QtGui
except ImportError:
    QtWidgets = QtCore = QtGui = None # Fallback to console-only logging

class GepettoStatusForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = None
        if QtWidgets is not None:
            try:
                self.parent = self.FormToPyQtWidget(form)
            except Exception:
                self.parent = None
        self._build_ui()

    def OnClose(self, form):
        from gepetto.ida.status_panel import panel
        panel.form_closed()

    def _build_ui(self):
        if QtWidgets is None or self.parent is None:
            return
        layout = QtWidgets.QVBoxLayout(self.parent)

        self._log = QtWidgets.QTextEdit()
        self._log.setReadOnly(True)
        try:
            self._log.document().setMaximumBlockCount(5000)
        except Exception:
            pass
        self._stream_active = False
        self._stream_prefix = ""

        controls_top = QtWidgets.QHBoxLayout()
        self._btn_clear = QtWidgets.QPushButton(_("Clear"))
        self._btn_clear.clicked.connect(self._log.clear)
        controls_top.addStretch(1)
        controls_top.addWidget(self._btn_clear)

        self._reason_label = QtWidgets.QLabel("placeholder for reasoning")
        self._reason_label.setStyleSheet("color: #888888;")
        self._reason_container = QtWidgets.QWidget()
        reasoning_row = QtWidgets.QHBoxLayout(self._reason_container)
        reasoning_row.addWidget(self._reason_label)
        reasoning_row.addStretch(1)
        self._reason_container.setVisible(False)

        self._model_label = QtWidgets.QLabel(_("Model: {model}").format(model=gepetto.config.get_config('Gepetto', 'MODEL')))
        self._status_label = QtWidgets.QLabel(_("Status: Idle"))
        self._progress = QtWidgets.QProgressBar()
        self._progress.setFixedHeight(15)
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._btn_stop = QtWidgets.QPushButton(_("Stop"))
        self._btn_stop.setVisible(False) # Hidden as per request

        bottom_row = QtWidgets.QHBoxLayout()
        bottom_row.addWidget(self._model_label)
        bottom_row.addStretch(1)
        bottom_row.addWidget(self._status_label)
        bottom_row.addWidget(self._progress)
        bottom_row.addWidget(self._btn_stop)

        layout.addLayout(controls_top)
        layout.addWidget(self._log)
        layout.addWidget(self._reason_container)
        layout.addLayout(bottom_row)

        # Reasoning/status animation timers (ellipses cadence)
        try:
            self._reason_base = ""
            self._dot_idx = 0
            self._dots = ["", ".", "..", "..."]
            self._reason_timer = QtCore.QTimer(self.parent)
            self._reason_timer.setInterval(300)  # 300 ms cadence
            self._reason_timer.timeout.connect(self._tick_reasoning)
        except Exception:
            pass

        # Mark as ready and request flush of any pending logs/status
        try:
            self.is_ready = True
            if QtCore is not None:
                # Defer flush to next iteration of the event loop
                from gepetto.ida.status_panel import panel  # late import to avoid circular refs
                QtCore.QTimer.singleShot(0, panel._flush_via_exec)
        except Exception:
            pass

    # Force cursor to the very end of the document to prevent user interference
    def _force_cursor_to_end(self):
        if QtGui is None:
            return
        self._log.moveCursor(QtGui.QTextCursor.End)

    # Ensure subsequent insertions use default (non-italic, default color) format
    def _reset_char_format(self):
        if QtGui is None:
            return
        self._force_cursor_to_end()
        cursor = self._log.textCursor()
        fmt = QtGui.QTextCharFormat()
        fmt.setFontItalic(False)
        fmt.clearForeground()
        cursor.setCharFormat(fmt)
        self._log.setTextCursor(cursor)

    # Ensure the cursor is at the start of a line (not mid-line) by inserting
    # exactly one newline only when needed. Avoid paragraph insertions that can
    # introduce extra spacing in QTextEdit.
    def _ensure_line_start(self):
        if QtGui is None:
            return
        try:
            # If the current document already ends with a newline (including <br/>)
            # or is empty, do nothing; else add exactly one newline.
            doc_text = self._log.toPlainText()
            if doc_text and not doc_text.endswith("\n"):
                self._log.moveCursor(QtGui.QTextCursor.End)
                self._log.insertPlainText("\n")
        except Exception:
            pass

    def _ensure_trailing_newline(self):
        if QtGui is None:
            return
        try:
            doc_text = self._log.toPlainText()
            if not doc_text.endswith("\n"):
                self._log.moveCursor(QtGui.QTextCursor.End)
                self._log.insertPlainText("\n")
        except Exception:
            pass


    # ------------------------------ API ------------------------------
    def set_model(self, model_name: str):
        if QtWidgets is None or self.parent is None:
            return
        self._model_label.setText(_("Model: {model_name}").format(model_name=model_name))

    def set_status(self, text: str, busy: Optional[bool] = None):
        if QtWidgets is None or self.parent is None:
            return

        # self.append_log(f"Status changed: {text}")

        if busy is True:
            self._status_label.setText(text)
            self._progress.setVisible(True)
            return

        lower = (text or "").strip().lower()
        if lower == "done":
            self._status_label.setText(_("Status: Done"))
        elif lower == "idle" or not lower:
            self._status_label.setText(_("Status: Idle"))
        else:
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
        # # Apply simple filter: hide noisy tool lines when unchecked
        # if hasattr(self, "_show_tool_calls") and not self._show_tool_calls.isChecked():
        #     if line.startswith("→ "):
        #         return
        # Ensure each log entry starts at the beginning of a line
        self._ensure_line_start()
        self._force_cursor_to_end()
        self._reset_char_format()
        self._log.insertPlainText(entry)
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def append_stream(self, text: str, prefix: str = _("Gepetto: ")):
        if QtWidgets is None or self.parent is None or QtGui is None:
            return

        self._force_cursor_to_end()

        if not self._stream_active:
            self._stream_active = True
            self._stream_prefix = prefix
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            header = f"{timestamp} | {prefix}"
            self._ensure_line_start()
            self._reset_char_format()
            self._log.insertPlainText(header)

        self._force_cursor_to_end()
        self._log.insertPlainText(text)
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def end_stream(self):
        if QtWidgets is None or self.parent is None or QtGui is None:
            return
        if not getattr(self, "_stream_active", False):
            return
        self._ensure_trailing_newline()
        self._stream_active = False
        self._stream_prefix = ""
        self._reset_char_format()

    # Styled helpers ------------------------------------------------------
    def append_html(self, html: str):
        if QtWidgets is None or self.parent is None or QtGui is None:
            # Fallback strip HTML
            import re as _re
            plain = _re.sub(r"<[^>]+>", "", html)
            try:
                print(plain, end="")
            except Exception as e:
                _debug_log(e)
            return
        # Force cursor to end to prevent user interference
        self._force_cursor_to_end()
        try:
            self._log.insertHtml(html)
        except Exception as e:
            _debug_log(e)
            # Fallback to plain text on failure
            self._log.insertPlainText(html)
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def append_line_html(self, html: str):
        # Use <br/> for explicit line breaks in HTML context
        self.append_html(html + "<br/>")

    def append_user(self, text: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        import html as _html
        safe = _html.escape(text).replace("\n", "<br/>")
        user_name = _html.escape(_("User"))
        html = f"{ts} | <b>{user_name}</b>: {safe}"
        self.append_line_html(html)

    def append_answer_stream(self, text: str, model_name: str):
        if QtWidgets is None or self.parent is None or QtGui is None:
            # Console fallback handled by manager
            return
        # Initialize the stream line if needed, with bold model name
        if not self._stream_active:
            self._stream_active = True
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            import html as _html
            safe_model = _html.escape(model_name)
            header_html = f"{ts} | <b>{safe_model}</b>: "
            # Force cursor to end to prevent user interference
            self._force_cursor_to_end()
            # Ensure we begin at the start of a line for the answer header
            self._ensure_line_start()
            # Ensure default formatting for answer header
            self._reset_char_format()
            try:
                self._log.insertHtml(header_html)
            except Exception:
                self._log.insertPlainText(f"{ts} | {model_name}: ")
        # Force cursor to end again before inserting plain text
        self._force_cursor_to_end()
        # Append the plain text portion
        self._reset_char_format()
        self._log.insertPlainText(text)
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

class _StatusPanelManager:
    def __init__(self):
        self._form: Optional[GepettoStatusForm] = None
        self._pending_model: Optional[str] = None
        self._pending_status: Optional[tuple[str, Optional[bool]]] = None
        self._pending_logs: list[str] = []
        self._pending_stream_prefix: Optional[str] = None
        self._pending_stream_text: list[str] = []
        self._fallback_stream_active = False
        self._stream_buffer: list[str] = []
        self._stream_prefix_for_batch: Optional[str] = None
        self._last_flush_time = 0
        self._on_stop = None
        self._stopped = False
        self._docked = False

    def _is_ready(self) -> bool:
        return bool(self._form and getattr(self._form, "_log", None))

    def _flush_pending_ui(self):
        if not self._is_ready():
            return
        if self._pending_model is not None:
            try:
                self._form.set_model(self._pending_model)
            except Exception:
                pass
            self._pending_model = None
        if self._pending_status is not None:
            text, busy = self._pending_status
            try:
                self._form.set_status(text, busy)
            except Exception:
                pass
            self._pending_status = None
        if self._pending_logs:
            for line in self._pending_logs:
                try:
                    self._form.append_log(line)
                except Exception:
                    pass
            self._pending_logs.clear()
        if self._pending_stream_text:
            try:
                prefix = self._pending_stream_prefix or _("Gepetto: ")
                self._form.append_stream("".join(self._pending_stream_text), prefix)
            except Exception:
                pass
            self._pending_stream_text.clear()
            self._pending_stream_prefix = None

    def _flush_via_exec(self):
        try:
            ida_kernwin.execute_sync(lambda: (self._flush_pending_ui() or 1), ida_kernwin.MFF_READ)
        except Exception:
            pass

    def ensure_shown(self):
        if self._form is not None:
            try:
                self._form.Show()
                return
            except Exception:
                pass
        try:
            if self._form is None:
                self._form = GepettoStatusForm()
                self._form.Show(
                    _("Gepetto Status"),
                    options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT),
                )
                if QtCore is not None:
                    QtCore.QTimer.singleShot(0, self._flush_via_exec)
                return
        except Exception:
            pass
        def _do():
            try:
                if self._form is None:
                    self._form = GepettoStatusForm()
                    self._form.Show(
                        _("Gepetto Status"),
                        options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT),
                    )
                    if QtCore is not None:
                        QtCore.QTimer.singleShot(0, self._flush_via_exec)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            try:
                print(_("Could not show Gepetto Status panel."))
            except Exception:
                pass

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
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
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
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def log_stream(self, text: str, prefix: str = _("Gepetto: ")):
        if getattr(self, "_stopped", False):
            return
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

        punct = {" ", "\n", "\t", ".", ",", ";", ":", "!", "?", ")", "]", "}"}
        last = text[-1:] if text else ""
        if any(ch in text for ch in punct) or last in punct or len("".join(self._stream_buffer)) >= 160:
            self._flush_stream_buffer()

    # ----------------------- Styled convenience APIs ---------------------
    def log_user(self, text: str):
        if not self._is_ready():
            self._pending_logs.append(_("User: {text}").format(text=text))
            return
        def _do():
            try:
                self._form.append_user(text)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def summary_stream_start(self, model_name: str):
        # Reset stop flag at the start of a new reasoning stream
        self._stopped = False
        if not self._is_ready():
            self._pending_logs.append(_("{model_name} reasoning...").format(model_name=model_name))
            return
        def _do():
            try:
                self._form.start_summary_stream(model_name)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def summary_stream(self, text: str):
        if getattr(self, "_stopped", False):
            return
        if not self._is_ready():
            self._pending_logs.append(text)
            return
        def _do():
            try:
                self._form.append_summary_stream(text)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def summary_stream_end(self):
        if not self._is_ready():
            return
        def _do():
            try:
                self._form.end_summary_stream()
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def answer_stream(self, text: str, model_name: str):
        if getattr(self, "_stopped", False):
            return
        if not self._is_ready():
            self._pending_stream_prefix = f"{model_name}: "
            self._pending_stream_text.append(text)
            return
        def _do():
            try:
                self._form.append_answer_stream(text, model_name)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    # ----------------------- Reasoning streaming API ----------------------
    def set_reasoning(self, text: str):
        self._pending_reasoning_text = text
        if not self._is_ready():
            return
        def _do():
            try:
                self._form.set_reasoning_text(text)
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def reasoning_stream(self, text_delta: str):
        if getattr(self, "_stopped", False):
            return
        if not self._is_ready():
            # Coalesce while not ready; last write wins when flushed
            self._pending_reasoning_text = (self._pending_reasoning_text or "") + (text_delta or "")
            return
        self._reasoning_buffer.append(text_delta)
        # Flush on whitespace heuristic similar to log_stream
        punct = {" ", "\n", "\t", ".", ",", ";", ":", "!", "?", ")", "]", "}"}
        last = text_delta[-1:] if text_delta else ""
        if any(ch in text_delta for ch in punct) or last in punct or len("".join(self._reasoning_buffer)) >= 160:
            joined = "".join(self._reasoning_buffer)
            self._reasoning_buffer.clear()
            def _do():
                try:
                    self._form.append_reasoning_delta(joined)
                except Exception:
                    return 0
                return 1
            try:
                ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
            except Exception:
                pass

    def clear_reasoning(self):
        self._pending_reasoning_text = ""
        if not self._is_ready():
            return
        def _do():
            try:
                self._form.clear_reasoning()
            except Exception:
                return 0
            return 1
        try:
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def end_stream(self):
        self._flush_stream_buffer()

        if not self._is_ready():
            try:
                if self._pending_stream_text:
                    combined = f"{self._pending_stream_prefix or ''}{''.join(self._pending_stream_text)}"
                    self._pending_logs.append(combined)
                if self._fallback_stream_active:
                    print()
            except Exception:
                pass
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
            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        except Exception:
            pass

    def dock(self):
        if self._docked or self._form is None:
            return
        try:
            tw = self._form.GetWidget()
            if hasattr(ida_kernwin, "find_widget") and hasattr(ida_kernwin, "set_dock_pos"):
                main_window = None
                for widget in QtWidgets.QApplication.topLevelWidgets():
                    if isinstance(widget, QtWidgets.QMainWindow):
                        main_window = widget
                        break
                if main_window is not None:
                    ida_kernwin.set_dock_pos(tw, main_window, getattr(ida_kernwin, "DP_RIGHT", 2), 0, 0, 0, 0, True)
                    self._docked = True
        except Exception:
            pass

    def form_closed(self):
        self._form = None


# Singleton instance
panel = _StatusPanelManager()
