import datetime
from typing import Optional

import ida_kernwin
import gepetto.config

_ = gepetto.config._

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
        from gepetto.ida.status_panel import panel
        panel.form_closed()

    def _build_ui(self):
        if QtWidgets is None or self.parent is None:
            return
        layout = QtWidgets.QVBoxLayout(self.parent)

        # Log area (use QTextEdit to allow simple styling)
        self._log = QtWidgets.QTextEdit()
        self._log.setReadOnly(True)
        try:
            # QTextEdit doesn't have setMaximumBlockCount; cap document size via block count if available
            self._log.document().setMaximumBlockCount(5000)
        except Exception:
            pass
        # Streaming state
        self._stream_active = False
        self._stream_prefix = ""

        # Top controls: Show reasoning, Show tool calls, Clear + Stop (right-aligned)
        controls_top = QtWidgets.QHBoxLayout()
        self._show_reasoning = QtWidgets.QCheckBox(_("Show reasoning"))
        self._show_reasoning.setChecked(True)
        self._show_tool_calls = QtWidgets.QCheckBox(_("Show tool calls"))
        self._show_tool_calls.setChecked(True)
        self._btn_clear = QtWidgets.QPushButton(_("Clear"))
        self._btn_clear.clicked.connect(self._log.clear)
        controls_top.addWidget(self._show_reasoning)
        controls_top.addWidget(self._show_tool_calls)
        controls_top.addStretch(1)
        controls_top.addWidget(self._btn_clear)

        # Reasoning status summary label (standalone container under log)
        self._reason_label = QtWidgets.QLabel("")
        try:
            if QtGui is not None:
                pal = self.parent.palette()
                fg_color = pal.color(QtGui.QPalette.WindowText)
                bg_color = pal.color(QtGui.QPalette.Window)
                r = (fg_color.red() + bg_color.red()) // 2
                g = (fg_color.green() + bg_color.green()) // 2
                b = (fg_color.blue() + bg_color.blue()) // 2
                dim_color = QtGui.QColor(r, g, b)
                self._reason_label.setStyleSheet(f"color: {dim_color.name()};")
            else:
                self._reason_label.setStyleSheet("color: #888888;")
        except Exception:
            try:
                self._reason_label.setStyleSheet("color: #888888;")
            except Exception:
                pass
        # Dedicated container that auto-hides when no reasoning event is active
        self._reason_container = QtWidgets.QWidget()
        reasoning_row = QtWidgets.QHBoxLayout(self._reason_container)
        reasoning_row.addWidget(self._reason_label)
        reasoning_row.addStretch(1)
        self._reason_container.setVisible(False)

        # Bottom row: Status + progress on left; Model on right
        self._model_label = QtWidgets.QLabel(_("Model: {model}").format(model=gepetto.config.get_config('Gepetto', 'MODEL')))
        self._status_label = QtWidgets.QLabel(_("Status: Idle"))
        self._progress = QtWidgets.QProgressBar()
        self._progress.setFixedHeight(15)
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._btn_stop = QtWidgets.QPushButton(_("Stop"))
        # late import to avoid circular refs
        try:
            from gepetto.ida.status_panel import panel  
            self._btn_stop.clicked.connect(lambda: panel.request_stop())
        except Exception:
            pass
        bottom_row = QtWidgets.QHBoxLayout()
        bottom_row.addWidget(self._model_label)
        bottom_row.addStretch(1)
        bottom_row.addWidget(self._status_label)
        bottom_row.addWidget(self._progress)
        bottom_row.addWidget(self._btn_stop)

        # Compose layout
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

    # Ensure subsequent insertions use default (non-italic, default color) format
    def _reset_char_format(self):
        if QtGui is None:
            return
        cursor = self._log.textCursor()
        fmt = QtGui.QTextCharFormat()
        fmt.setFontItalic(False)
        # Clear explicit foreground color so palette text color is used
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
                self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
                self._log.insertPlainText("\n")
        except Exception:
            pass

    # Ensure there is exactly one trailing newline at the end of the document.
    def _ensure_trailing_newline(self):
        if QtGui is None:
            return
        try:
            doc_text = self._log.toPlainText()
            if not doc_text.endswith("\n"):
                self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
                self._log.insertPlainText("\n")
        except Exception:
            pass

    def _squash_trailing_blank_line(self):
        if QtGui is None:
            return
        try:
            doc = self._log.document()
            cursor = self._log.textCursor()
            # Loop: remove trailing whitespace-only blocks
            while True:
                block = doc.lastBlock()
                if not block.isValid():
                    break
                if block.text().strip() != "":
                    break
                # Delete the newline preceding the empty/whitespace block
                cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
                cursor.movePosition(QtGui.QTextCursor.MoveOperation.StartOfBlock)
                cursor.deletePreviousChar()
                # If multiple empties stacked, continue
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
        # Busy: animate ellipses with truncated base text
        if busy is True:
            try:
                self._status_base = self._truncate_for_status(text)
                if getattr(self, "_status_timer", None) is not None:
                    self._status_timer.start()
                self._render_status()
            except Exception:
                self._status_label.setText(text)
            self._progress.setVisible(True)
            return
        # Not busy: stop animation and show final state
        try:
            if getattr(self, "_status_timer", None) is not None:
                self._status_timer.stop()
            lower = (text or "").strip().lower()
            if lower == "done":
                self._status_label.setText(_("Status: Done"))
            elif lower == "idle" or not lower:
                self._status_label.setText(_("Status: Idle"))
            else:
                self._status_label.setText(text)
        except Exception:
            self._status_label.setText(text or _("Status: Idle"))
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
        # Apply simple filter: hide noisy tool lines when unchecked
        if hasattr(self, "_show_tool_calls") and not self._show_tool_calls.isChecked():
            if line.startswith("→ "):
                return
        # Ensure each log entry starts at the beginning of a line
        self._ensure_line_start()
        # Use the robust moveCursor + insertPlainText pattern
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        # Force default format (non-italic, default color)
        self._reset_char_format()
        self._log.insertPlainText(entry)
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    # Reasoning box helpers
    def set_reasoning_text(self, text: str):
        if QtWidgets is None or self.parent is None:
            return
        # Update base text and render without altering animation state
        try:
            self._reason_base = text or _("Reasoning")
            self.start_reasoning_animation()
            if hasattr(self, "_render_reasoning"):
                self._render_reasoning()
            else:
                self._reason_label.setText(self._reason_base)
        except Exception:
            pass

    def append_reasoning_delta(self, text: str):
        if QtWidgets is None or self.parent is None or QtGui is None:
            return
        try:
            # Coalesce into base text and re-render; keep ellipses animation running
            delta = (text or "").replace("\n", " ")
            self._reason_base = (self._reason_base or "") + delta
            if hasattr(self, "_render_reasoning"):
                self._render_reasoning()
            else:
                self._reason_label.setText(self._reason_base)
        except Exception:
            pass

    def clear_reasoning(self):
        if QtWidgets is None or self.parent is None:
            return
        try:
            self._reason_base = ""
            self._reason_label.setText("")
            self._reason_container.setVisible(False)
        except Exception:
            pass

    # Stream text into the log without creating new lines per chunk.
    # Starts a new timestamped row with the given prefix on first call,
    # then appends subsequent text to the same row.
    def append_stream(self, text: str, prefix: str = _("Gepetto: ")):
        if QtWidgets is None or self.parent is None or QtGui is None:
            return
        # Apply filters: hide tool streaming and detailed reasoning when unchecked
        if hasattr(self, "_show_tool_calls") and not self._show_tool_calls.isChecked():
            if str(prefix).startswith("→ "):
                return
        if hasattr(self, "_show_reasoning") and not self._show_reasoning.isChecked():
            if str(prefix).startswith(_("Reasoning: ")):
                return

        # Move cursor to the very end of the document
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)

        # Initialize the stream line if needed
        if not self._stream_active:
            self._stream_active = True
            self._stream_prefix = prefix
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            header = f"{timestamp} | {prefix}"
            # Ensure default formatting and start at line start for headers
            self._ensure_line_start()
            self._reset_char_format()
            self._log.insertPlainText(header)

        # Now, insert the new text at the cursor's current position
        self._log.insertPlainText(text)
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def end_stream(self):
        if QtWidgets is None or self.parent is None or QtGui is None:
            return
        if not getattr(self, "_stream_active", False):
            return
        # Finish the line with exactly one newline and reset state
        self._ensure_trailing_newline()
        self._stream_active = False
        self._stream_prefix = ""
        # Reset format to default after finishing a stream line
        self._reset_char_format()

    # Styled helpers ------------------------------------------------------
    def append_html(self, html: str):
        if QtWidgets is None or self.parent is None or QtGui is None:
            # Fallback strip HTML
            import re as _re
            plain = _re.sub(r"<[^>]+>", "", html)
            try:
                print(plain, end="")
            except Exception:
                pass
            return
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        try:
            self._log.insertHtml(html)
        except Exception:
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
        html = f"{ts} | <b>User</b>: {safe}"
        self.append_line_html(html)

    # Styled summary streaming (bold header + italic body)
    def start_summary_stream(self, model_name: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        import html as _html
        safe_model = _html.escape(model_name)
        header_html = f"{ts} | <b>{safe_model} reasoning...</b>"  # newline added below
        self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        try:
            # Start header at the beginning of a line
            self._ensure_line_start()
            self._log.insertHtml(header_html + "<br/>")
        except Exception:
            # Plain-text fallback, still respecting line boundaries
            self._ensure_line_start()
            self._log.insertPlainText(f"{ts} | {model_name} reasoning...\n")
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())
        # Start reasoning label animation and show the container
        try:
            if hasattr(self, "_reason_container"): # and self._show_reasoning.isChecked():
                self._reason_container.setVisible(True)
        except Exception:
            pass

    def append_summary_stream(self, text: str):
        # Gate detailed reasoning by the "Show reasoning" checkbox
        if hasattr(self, "_show_reasoning") and not self._show_reasoning.isChecked():
            return
        # Append italic plain text with preserved whitespace
        if QtGui is None:
            try:
                print(text, end="")
            except Exception:
                pass
            return
        cursor = self._log.textCursor()
        # Save current format and apply italic only for this insertion
        prev_fmt = cursor.charFormat()
        italic_fmt = QtGui.QTextCharFormat(prev_fmt)
        italic_fmt.setFontItalic(True)
        # Dim the summary text
        try:
            # italic_fmt.setForeground(QtGui.QBrush(QtGui.QColor(102, 102, 102)))  # #666
            pal = self._log.palette()
            fg_color = pal.color(QtGui.QPalette.Text)
            bg_color = pal.color(QtGui.QPalette.Base)
            r = (fg_color.red() + bg_color.red()) // 2
            g = (fg_color.green() + bg_color.green()) // 2
            b = (fg_color.blue() + bg_color.blue()) // 2
            dim_color = QtGui.QColor(r, g, b)
            italic_fmt.setForeground(QtGui.QBrush(dim_color))
        except Exception:
            pass
        cursor.setCharFormat(italic_fmt)
        cursor.insertText(text)
        cursor.setCharFormat(prev_fmt)
        # Always autoscroll
        self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def end_summary_stream(self):
        # Finish with exactly one newline for clean separation
        self._ensure_trailing_newline()
        # Reset format so following lines are not italic or dimmed
        self._reset_char_format()

    # Reasoning animation helpers
    def _render_reasoning(self):
        try:
            dots = getattr(self, "_dots", ["", ".", "..", "..."])
            idx = getattr(self, "_dot_idx", 0) % len(dots)
            self._reason_label.setText(f"{self._reason_base or ''}{dots[idx]}")
        except Exception:
            try:
                self._reason_label.setText(self._reason_base or "")
            except Exception:
                pass

    def _truncate_for_status(self, text: str, limit: int = 50) -> str:
        try:
            s = str(text or "")
        except Exception:
            s = ""
        if len(s) <= limit:
            return s
        return s[:limit] + " (trimmed)"

    def _render_status(self):
        try:
            dots = getattr(self, "_dots", ["", ".", "..", "..."])
            idx = getattr(self, "_status_dot_idx", 0) % len(dots)
            base = getattr(self, "_status_base", "") or ""
            self._status_label.setText(f"{base}{dots[idx]}")
        except Exception:
            pass

    def _tick_status(self):
        try:
            self._status_dot_idx = (getattr(self, "_status_dot_idx", 0) + 1) % len(getattr(self, "_dots", ["", ".", "..", "..."]))
            self._render_status()
        except Exception:
            pass

    def _tick_reasoning(self):
        try:
            self._dot_idx = (getattr(self, "_dot_idx", 0) + 1) % len(getattr(self, "_dots", ["", ".", "..", "..."]))
            self._render_reasoning()
        except Exception:
            pass

    def start_reasoning_animation(self, base_text: str = ""):
        try:
            self._dot_idx = 0
            if getattr(self, "_reason_timer", None) is not None:
                self._reason_timer.start()
            self._render_reasoning()
        except Exception:
            pass

    def stop_reasoning_animation(self):
        try:
            if getattr(self, "_reason_timer", None) is not None:
                self._reason_timer.stop()
            self._dot_idx = 0
            self._render_reasoning()
        except Exception:
            pass

    # Styled assistant answer streaming (bold model prefix)
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
            self._log.moveCursor(QtGui.QTextCursor.MoveOperation.End)
            # Ensure we begin at the start of a line for the answer header
            self._ensure_line_start()
            # Ensure default formatting for answer header
            self._reset_char_format()
            try:
                self._log.insertHtml(header_html)
            except Exception:
                self._log.insertPlainText(f"{ts} | {model_name}: ")
        # Append the plain text portion
        self._reset_char_format()
        self._log.insertPlainText(text)
        # Always autoscroll
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
        # Pending streaming state
        self._pending_stream_prefix: Optional[str] = None
        self._pending_stream_text: list[str] = []
        self._fallback_stream_active = False
        # New state for stream batching
        self._stream_buffer: list[str] = []
        self._stream_prefix_for_batch: Optional[str] = None
        self._last_flush_time = 0
        # Reasoning streaming buffer/state
        self._pending_reasoning_text: Optional[str] = None
        self._reasoning_buffer: list[str] = []
        # Stop/cancel support
        self._on_stop = None
        self._stopped = False
        self._docked = False

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
        prefix = self._pending_stream_prefix or _("Gepetto: ")
                self._form.append_stream("".join(self._pending_stream_text), prefix)
            except Exception:
                pass
            # Clear pending stream buffer after flush
            self._pending_stream_text.clear()
            self._pending_stream_prefix = None
        # Apply pending reasoning text
        if self._pending_reasoning_text is not None:
            try:
                self._form.set_reasoning_text(self._pending_reasoning_text)
            except Exception:
                pass
            self._pending_reasoning_text = None

    def _flush_via_exec(self):
        try:
            ida_kernwin.execute_sync(lambda: (self._flush_pending_ui() or 1), self._MFF_FAST)
        except Exception:
            pass

    def ensure_shown(self):
        # For menu/CLI activation, we're likely on the UI thread. Try direct Show().
        if self._form is not None:
            try:
                # If the form is already created, just show it
                self._form.Show()
                return
            except Exception:
                # If Show() fails, the form is likely in a bad state, so we recreate it
                # self._form = None
                pass
        try:
            if self._form is None:
                self._form = GepettoStatusForm()
                # Persist and dock to the right by default
                self._form.Show(
                    _("Gepetto Status"),
                    options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT),
                )
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
                        _("Gepetto Status"),
                        options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT),
                    )
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
                print(_("Could not show Gepetto Status panel."))
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

    def log_stream(self, text: str, prefix: str = _("Gepetto: ")):
        if getattr(self, "_stopped", False):
            return
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
                ida_kernwin.execute_sync(_do, self._MFF_FAST)
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
            ida_kernwin.execute_sync(_do, self._MFF_FAST)
        except Exception:
            pass

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

    def set_stop_callback(self, cb):
        """Register an optional callback invoked when the user presses Stop."""
        self._on_stop = cb

    def reset_stop(self):
        """Clear the stop flag to allow new streaming."""
        self._stopped = False

    def request_stop(self):
        """Immediately stop UI streaming and mark Idle; invoke backend stop if provided."""
        # Signal that streaming should be ignored from now on
        self._stopped = True
        # Try to end the current UI stream line, if any
        try:
            if self._is_ready():
                def _do():
                    try:
                        self._form.end_stream()
                    except Exception:
                        return 0
                    return 1
                ida_kernwin.execute_sync(_do, self._MFF_FAST)
        except Exception:
            pass
        # Update status/log
        try:
            self.set_status(_("Idle"), busy=False)
            # Ensure the stop log message appears even if streaming is stopped
            def _do_log():
                try:
                    # Add a concise cancellation footer and provider-specific note
                    try:
                        import gepetto.config as _cfg
                        provider = getattr(_cfg.model, "get_menu_name", lambda: _("Model"))()
                        note = None
                        if provider == "OpenAI":
                            note = _("Requested stream close; server cancels promptly. Residual buffered tokens may appear; ignored.")
                        elif provider == "Google Gemini":
                            note = _("Best-effort stream close requested; upstream may compute briefly; further output is ignored.")
                        else:
                            note = _("Cancellation requested upstream; further output (if any) is ignored.")
                        self._form.append_log(_("Canceled."))
                        if note:
                            self._form.append_log(note)
                    except Exception:
                        self._form.append_log(_("Canceled."))
                        pass
                    self._reason_container.setVisible(False)
                except Exception:
                    return 0
                return 1
            ida_kernwin.execute_sync(_do_log, self._MFF_FAST)
        except Exception:
            pass
        # Invoke backend cancellation, if registered
        try:
            if self._on_stop:
                self._on_stop()
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
