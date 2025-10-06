
"""Enhanced Qt5 status panel for Gepetto streaming UX."""

from __future__ import annotations

import ida_kernwin
import datetime
import html
from dataclasses import dataclass
from enum import Enum
from collections.abc import Callable
from PyQt5 import QtCore, QtGui, QtWidgets
from gepetto.ida.hooks import run_when_desktop_ready

import gepetto.config

_ = gepetto.config._

STATUS_PANEL_CAPTION = _("Gepetto")
_DEFAULT_DOCK_OPTIONS = (
    getattr(ida_kernwin.PluginForm, "WOPN_RESTORE", 0x04)
    | getattr(ida_kernwin.PluginForm, "WOPN_MENU", 0x10)
    | getattr(ida_kernwin.PluginForm, "WOPN_PERSIST", 0x40)
    | getattr(ida_kernwin.PluginForm, "WOPN_NOT_CLOSED_BY_ESC", 0x100)
    | getattr(ida_kernwin.PluginForm, "WOPN_DP_SZHINT", 0x200)
)

class LogLevel(Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"


class LogCategory(Enum):
    SYSTEM = "system"
    USER = "user"
    TOOL = "tool"
    MODEL = "model"
    ASSISTANT = "assistant"

    def display_name(self) -> str:
        labels = {
            LogCategory.SYSTEM: _("System"),
            LogCategory.USER: _("User"),
            LogCategory.TOOL: _("Tool"),
            LogCategory.MODEL: _("Model"),
            LogCategory.ASSISTANT: _("Assistant"),
        }
        return labels[self]


@dataclass
class LogEntry:
    timestamp: datetime.datetime
    level: LogLevel
    category: LogCategory
    message: str
    trailing_breaks: int = 0


def _html_escape(text: str) -> str:
    return html.escape(text).replace("\n", "<br>")


def _relative_luminance(color: QtGui.QColor) -> float:
    if not color.isValid():
        return 0.0

    def _channel(value: int) -> float:
        norm = value / 255.0
        if norm <= 0.03928:
            return norm / 12.92
        return ((norm + 0.055) / 1.055) ** 2.4

    r = _channel(color.red())
    g = _channel(color.green())
    b = _channel(color.blue())
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast_ratio(foreground: QtGui.QColor, background: QtGui.QColor) -> float:
    if not (foreground.isValid() and background.isValid()):
        return 1.0
    l1 = _relative_luminance(foreground)
    l2 = _relative_luminance(background)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def _best_text_color(background: QtGui.QColor, palette: QtGui.QPalette) -> QtGui.QColor:
    candidates = [
        palette.color(QtGui.QPalette.Shadow),
        palette.color(QtGui.QPalette.WindowText),
        palette.color(QtGui.QPalette.Text),
        palette.color(QtGui.QPalette.ButtonText),
        palette.color(QtGui.QPalette.BrightText),
        QtGui.QColor("black"),
        QtGui.QColor("white"),
    ]
    return max(candidates, key=lambda c: _contrast_ratio(c, background))


class GepettoStatusForm(ida_kernwin.PluginForm):
    """Dockable widget that displays the streaming answer and structured log."""

    _CATEGORY_COLORS = {
        LogCategory.SYSTEM: "#bac2de",
        LogCategory.USER: "#89b4fa",
        LogCategory.TOOL: "#f9e2af",
        LogCategory.MODEL: "#f5c2e7",
        LogCategory.ASSISTANT: "#a6e3a1",
    }
    _LEVEL_COLORS = {
        LogLevel.INFO: "",
        LogLevel.SUCCESS: "#a6e3a1",
        LogLevel.WARNING: "#f9e2af",
        LogLevel.ERROR: "#f38ba8",
        LogLevel.DEBUG: "#94e2d5",
    }

    def __init__(self, owner: "_StatusPanelManager") -> None:
        if QtWidgets is None:
            return
        super().__init__()
        self._owner = owner
        self._category_color_map = {
            category: QtGui.QColor(color) for category, color in self._CATEGORY_COLORS.items() if color
        }
        self._level_color_map = {
            level: QtGui.QColor(color) for level, color in self._LEVEL_COLORS.items() if color
        }
        self._widget: QtWidgets.QWidget | None = None
        self._twidget = None
        self._model_label: QtWidgets.QLabel | None = None
        self._status_label: QtWidgets.QLabel | None = None
        self._stop_button: QtWidgets.QPushButton | None = None
        self._clear_button: QtWidgets.QPushButton | None = None
        self._reasoning_button: QtWidgets.QToolButton | None = None
        self._progress_bar: QtWidgets.QProgressBar | None = None
        self._conversation_view: QtWidgets.QTextBrowser | None = None
        self._reasoning_view: QtWidgets.QTextBrowser | None = None
        self._reasoning_frame: QtWidgets.QFrame | None = None
        self._log_view: QtWidgets.QTextBrowser | None = None
        self._filter_buttons: dict[LogCategory, QtWidgets.QToolButton] = {}
        self._active_filters: set[LogCategory] = set(LogCategory)
        self._log_entries: list[LogEntry] = []
        self._conversation_segments: list[str] = []
        self._stream_text: list[str] = []
        self._stream_index: int | None = None
        self._stream_active = False
        self._stream_header: str | None = None
        self._reasoning_chunks: list[str] = []
        self._reasoning_dirty = False
        self._ready = False

    # ------------------------------------------------------------------
    def OnCreate(self, form):  # noqa: N802 - IDA callback signature
        if QtWidgets is None:
            return
        self._twidget = self.GetWidget()
        self._widget = self.FormToPyQtWidget(form)
        self._build_ui()
        self._ready = True
        self._owner.on_form_ready()

    # ------------------------------------------------------------------
    def OnClose(self, form):  # noqa: N802 - IDA callback signature
        del form
        self._twidget = None
        self._widget = self._model_label = self._status_label = None
        self._stop_button = self._clear_button = self._reasoning_button = self._progress_bar = None
        self._conversation_view = self._reasoning_view = self._reasoning_frame = self._log_view = None
        self._filter_buttons = {}
        self._active_filters = set(LogCategory)
        self._log_entries.clear()
        self._conversation_segments.clear()
        self._stream_text.clear()
        self._reasoning_chunks.clear()
        self._stream_index = self._stream_header = None
        self._stream_active = self._reasoning_dirty = False
        self._ready = False
        self._owner.form_closed()

    # ------------------------------------------------------------------
    def is_ready(self) -> bool:
        return bool(self._widget and self._ready)

    # ------------------------------------------------------------------
    def widget(self):  # noqa: ANN001 - helper used by the manager
        return self._widget

    # ------------------------------------------------------------------
    def twidget(self):  # noqa: ANN001 - helper used by the manager
        return self._twidget

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        if QtWidgets is None or self._widget is None:
            return

        layout = QtWidgets.QVBoxLayout(self._widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        header = QtWidgets.QHBoxLayout()
        header.setSpacing(8)
        self._model_label = QtWidgets.QLabel(_("Model: {model}").format(model=str(gepetto.config.model)))
        self._model_label.setObjectName("gepetto_status_model_label")
        header.addWidget(self._model_label)

        header.addStretch(1)

        self._status_label = QtWidgets.QLabel(_("Status: {status}").format(status=_("Idle")))
        self._status_label.setObjectName("gepetto_status_label")

        self._progress_bar = QtWidgets.QProgressBar()
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(1)
        self._progress_bar.setFixedWidth(120)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.hide()
        header.addWidget(self._progress_bar)

        self._reasoning_button = QtWidgets.QToolButton()
        self._reasoning_button.setText(_("Reasoning"))
        self._reasoning_button.setCheckable(True)
        self._reasoning_button.setEnabled(False)
        self._reasoning_button.toggled.connect(self._set_reasoning_visible)  # type: ignore[arg-type]
        header.addWidget(self._reasoning_button)

        self._stop_button = QtWidgets.QPushButton(_("Stop"))
        self._stop_button.setEnabled(False)
        self._stop_button.clicked.connect(self._handle_stop_clicked)  # type: ignore[arg-type]
        header.addWidget(self._stop_button)

        self._clear_button = QtWidgets.QPushButton(_("Clear"))
        self._clear_button.clicked.connect(self._owner.clear_log)  # type: ignore[arg-type]
        header.addWidget(self._clear_button)

        layout.addLayout(header)

        filters_row = QtWidgets.QHBoxLayout()
        filters_row.setSpacing(4)
        filters_row_label = QtWidgets.QLabel(_("Log filters:"))
        filters_row.addWidget(filters_row_label)
        for category in LogCategory:
            button = QtWidgets.QToolButton()
            button.setText(category.display_name())
            button.setCheckable(True)
            button.setChecked(True)
            button.clicked.connect(self._make_filter_callback(category))  # type: ignore[arg-type]
            filters_row.addWidget(button)
            # turn off repeat of final message in log by default
            if category is LogCategory.ASSISTANT:
                button.click()
            self._filter_buttons[category] = button
        self._apply_filter_styles()
        filters_row.addSpacing(12)
        filters_row.addWidget(self._status_label)
        filters_row.addStretch(1)
        layout.addLayout(filters_row)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        conversation_container = QtWidgets.QWidget()
        conversation_layout = QtWidgets.QVBoxLayout(conversation_container)
        conversation_layout.setContentsMargins(0, 0, 0, 0)
        conversation_layout.setSpacing(6)

        self._conversation_view = QtWidgets.QTextBrowser()
        self._conversation_view.setReadOnly(True)
        self._conversation_view.setMinimumHeight(160)
        self._conversation_view.setOpenExternalLinks(False)
        conversation_layout.addWidget(self._conversation_view)

        self._reasoning_frame = QtWidgets.QFrame()
        self._reasoning_frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self._reasoning_frame.setStyleSheet(
            "QFrame {"
            "  background-color: rgba(56, 66, 89, 200);"
            "  border: 1px solid rgba(148, 226, 213, 120);"
            "  border-radius: 6px;"
            "}"
            "QTextBrowser {"
            "  background: transparent;"
            "  color: #f8f9fa;"
            "  font-style: italic;"
            "}"
        )
        reasoning_layout = QtWidgets.QVBoxLayout(self._reasoning_frame)
        reasoning_layout.setContentsMargins(8, 8, 8, 8)
        reasoning_layout.setSpacing(4)
        label = QtWidgets.QLabel(_("Reasoning stream"))
        label.setStyleSheet("color: #94e2d5;")
        reasoning_layout.addWidget(label)
        self._reasoning_view = QtWidgets.QTextBrowser()
        self._reasoning_view.setReadOnly(True)
        reasoning_layout.addWidget(self._reasoning_view)
        self._reasoning_frame.hide()
        conversation_layout.addWidget(self._reasoning_frame)

        splitter.addWidget(conversation_container)

        self._log_view = QtWidgets.QTextBrowser()
        self._log_view.setReadOnly(True)
        self._log_view.setMinimumHeight(120)
        splitter.addWidget(self._log_view)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

        self._refresh_conversation(scroll=False)
        self._refresh_log_widget(scroll=False)

    # ------------------------------------------------------------------
    def _make_filter_callback(self, category: LogCategory) -> Callable[[bool], None]:
        def toggle(checked: bool) -> None:
            if checked:
                self._active_filters.add(category)
            else:
                self._active_filters.discard(category)
            self._refresh_log_widget(scroll=False)

        return toggle

    # ------------------------------------------------------------------
    def _apply_filter_styles(self) -> None:
        if not self._filter_buttons:
            return
        palette = self._widget.palette() if self._widget else QtWidgets.QApplication.palette()
        muted_text_color = palette.color(QtGui.QPalette.Shadow)
        muted_color = palette.color(QtGui.QPalette.ColorRole.Midlight).darker(100)

        for category, button in self._filter_buttons.items():
            base_color = QtGui.QColor(self._CATEGORY_COLORS.get(category, ""))
            if not button or not base_color.isValid():
                if button:
                    button.setStyleSheet("")
                continue

            text_color = _best_text_color(base_color, palette)
            border_color = QtGui.QColor(base_color)
            border_color = border_color.darker(140)
            hover_color = QtGui.QColor(base_color)
            if _relative_luminance(base_color) > _relative_luminance(palette.color(QtGui.QPalette.Button)):
                hover_color = base_color.darker(110)
            else:
                hover_color = base_color.lighter(120)

            style = (
                "QToolButton {"
                "  padding: 2px 10px;"
                "  border-radius: 4px;"
                f"  border: 1px solid {base_color.name()};"
                "}"
                "QToolButton:checked {"
                f"  background-color: {base_color.name()};"
                f"  color: {text_color.name()};"
                f"  border: 1px solid {border_color.name()};"
                "  font-weight: bold;"
                "}"
                "QToolButton:hover {"
                f"  background-color: {hover_color.name()};"
                f"  border: 1px solid {border_color.name()};"
                "}"
                "QToolButton:!checked {"
                f"  background-color: {muted_color.name()} !important;"
                f"  color: {muted_text_color.name()};"
                f"  border: 1px solid {muted_color.name()};"
                "  font-weight: normal;"
                "}"
                "QToolButton:!checked:hover {"
                f"  border: 1px solid {border_color.darker(200).name()};"
                "}"
            )
            button.setStyleSheet(style)

    # ------------------------------------------------------------------
    def _handle_stop_clicked(self) -> None:
        self._owner.request_stop()

    # ------------------------------------------------------------------
    @staticmethod
    def _set_text_browser_content(browser: QtWidgets.QTextBrowser, content: str) -> None:
        try:
            browser.setMarkdown(content)
        except Exception:
            browser.setPlainText(content)

    # ------------------------------------------------------------------
    def _set_reasoning_visible(self, visible: bool) -> None:
        if not self._reasoning_frame or not self._reasoning_button:
            return
        self._reasoning_frame.setVisible(visible)
        if visible:
            self._reasoning_dirty = False
            self._refresh_reasoning(scroll=True)
        self._update_reasoning_button()

    # ------------------------------------------------------------------
    def _update_reasoning_button(self) -> None:
        if not self._reasoning_button:
            return
        text = _("Reasoning")
        if self._reasoning_dirty and not self._reasoning_button.isChecked():
            text += " ●"
        self._reasoning_button.setText(text)
        self._reasoning_button.setEnabled(bool(self._reasoning_chunks))

    # ------------------------------------------------------------------
    def _refresh_conversation(self, *, scroll: bool) -> None:
        if not self._conversation_view:
            return
        content = "\n\n".join(self._conversation_segments)
        self._set_text_browser_content(self._conversation_view, content)
        if scroll:
            cursor = self._conversation_view.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)
            self._conversation_view.setTextCursor(cursor)
            self._conversation_view.ensureCursorVisible()

    # ------------------------------------------------------------------
    def _refresh_log_widget(self, *, scroll: bool) -> None:
        if not self._log_view:
            return
        visible_entries = [entry for entry in self._log_entries if entry.category in self._active_filters]
        palette = self._log_view.palette()
        base_color = palette.color(QtGui.QPalette.Base)
        default_text_color = palette.color(QtGui.QPalette.Text)

        if not visible_entries:
            self._log_view.clear()
        else:
            html_parts: list[str] = []
            for entry in visible_entries:
                level_color = self._LEVEL_COLORS.get(entry.level, "")
                category_color = self._CATEGORY_COLORS.get(entry.category, "#cdd6f4")
                color = level_color or category_color
                timestamp = entry.timestamp.strftime("%H:%M:%S")
                text = _html_escape(entry.message)
                line = f"[{timestamp}] {text}"
                desired = QtGui.QColor(color)
                effective = self._ensure_contrast_color(
                    desired, fallback=default_text_color, background=base_color, palette=palette
                )
                line = f"<span style='color:{effective.name()};'>{line}</span>"
                line += "<br>"
                if entry.trailing_breaks:
                    line += "<br>" * entry.trailing_breaks
                html_parts.append(line)
            self._log_view.setHtml("".join(html_parts))
        if scroll:
            self._log_view.moveCursor(QtGui.QTextCursor.End)
            self._log_view.ensureCursorVisible()

    # ------------------------------------------------------------------
    def _ensure_contrast_color(
        self,
        desired: QtGui.QColor,
        *,
        fallback: QtGui.QColor,
        background: QtGui.QColor,
        palette: QtGui.QPalette,
    ) -> QtGui.QColor:
        if not desired.isValid():
            return fallback

        if _contrast_ratio(desired, background) >= 4.0:
            return desired

        base = QtGui.QColor(desired)
        lighten = _relative_luminance(desired) <= _relative_luminance(background)
        for factor in (120, 140, 160, 180, 200):
            candidate = base.lighter(factor) if lighten else base.darker(factor)
            if _contrast_ratio(candidate, background) >= 4.0:
                return candidate

        best = _best_text_color(background, palette)
        return best if _contrast_ratio(best, background) >= 4.0 else fallback

    # ------------------------------------------------------------------
    def _refresh_reasoning(self, *, scroll: bool) -> None:
        if not self._reasoning_view:
            return
        text = "".join(self._reasoning_chunks)
        self._set_text_browser_content(self._reasoning_view, text)
        if scroll:
            self._reasoning_view.moveCursor(QtGui.QTextCursor.End)
            self._reasoning_view.ensureCursorVisible()

    # ------------------------------------------------------------------
    def set_model(self, model_name: str) -> None:
        if self._model_label:
            self._model_label.setText(_("Model: {model}").format(model=model_name))

    # ------------------------------------------------------------------
    def set_status(self, text: str, *, busy: bool = False, error: bool = False) -> None:
        if not self._status_label:
            return
        status_text = text or _("Idle")
        self._status_label.setText(_("Status: {status}").format(status=status_text))
        if error:
            self._status_label.setStyleSheet("color: #f38ba8;")
        else:
            self._status_label.setStyleSheet("")
        if self._progress_bar:
            if busy:
                self._progress_bar.setRange(0, 0)
                self._progress_bar.show()
            else:
                self._progress_bar.setRange(0, 1)
                self._progress_bar.setValue(1)
                self._progress_bar.hide()

    # ------------------------------------------------------------------
    def reset_stop(self) -> None:
        if not self._stop_button:
            return
        self._stop_button.setText(_("Stop"))
        self._stop_button.setEnabled(self._owner.has_stop_callback())

    # ------------------------------------------------------------------
    def set_stop_callback(self, callback: Callable[[], None] | None) -> None:
        if not self._stop_button:
            return
        self._stop_button.setEnabled(callback is not None)

    # ------------------------------------------------------------------
    def mark_error(self, message: str) -> None:
        self.append_log(message, category=LogCategory.SYSTEM, level=LogLevel.ERROR)
        self.set_status(message, error=True)
        if self._stop_button:
            self._stop_button.setEnabled(False)

    # ------------------------------------------------------------------
    def mark_cancelling(self) -> None:
        if self._stop_button:
            self._stop_button.setText(_("Cancelling…"))
            self._stop_button.setEnabled(False)
        self.set_status(_("Cancelling request"), busy=True)

    # ------------------------------------------------------------------
    def clear_log(self) -> None:
        for collection in (
            self._log_entries,
            self._conversation_segments,
            self._stream_text,
            self._reasoning_chunks,
        ):
            collection.clear()
        self._stream_index = self._stream_header = None
        self._stream_active = self._reasoning_dirty = False
        if self._reasoning_button:
            self._reasoning_button.setChecked(False)
        self._refresh_conversation(scroll=False)
        self._refresh_log_widget(scroll=False)
        self._refresh_reasoning(scroll=False)
        self._update_reasoning_button()

    # ------------------------------------------------------------------
    def append_log(
        self,
        message: str,
        newline: bool = False,
        *,
        category: LogCategory = LogCategory.SYSTEM,
        level: LogLevel = LogLevel.INFO,
    ) -> None:
        entry = LogEntry(
            timestamp=datetime.datetime.now(),
            level=level,
            category=category,
            message=message,
            trailing_breaks=1 if newline else 0,
        )
        self._log_entries.append(entry)
        self._refresh_log_widget(scroll=True)

    # ------------------------------------------------------------------
    def log_user(self, text: str) -> None:
        if not text:
            return
        label = _("You")
        self._conversation_segments.append(f"**[{label}]**: {text}")
        self.append_log(_("User: {text}").format(text=text), category=LogCategory.USER)
        self._refresh_conversation(scroll=True)

    # ------------------------------------------------------------------
    def _log_assistant_event(self, text: str) -> None:
        if text:
            self.append_log(_("Assistant: {text}").format(text=text), category=LogCategory.ASSISTANT)

    # ------------------------------------------------------------------
    def log_assistant(self, text: str) -> None:
        if not text:
            return
        label = _("Gepetto")
        self._conversation_segments.append(f"**[{label}]**: {text}")
        self._log_assistant_event(text)
        self._refresh_conversation(scroll=True)

    # ------------------------------------------------------------------
    def start_stream(self) -> None:
        model_name = str(gepetto.config.model)
        label = _("Gepetto")
        header = f"**[{label}]"
        if model_name:
            header += f" ({model_name})"
        header += "**: "
        self._stream_text = []
        self._stream_active = True
        self._stream_header = header
        self._stream_index = len(self._conversation_segments)
        self._conversation_segments.append(header)
        self._reasoning_chunks.clear()
        self._reasoning_dirty = False
        if self._reasoning_button:
            self._reasoning_button.setChecked(False)
        self._refresh_conversation(scroll=True)
        self._refresh_reasoning(scroll=False)
        self._update_reasoning_button()

    # ------------------------------------------------------------------
    def append_stream(self, chunk: str) -> None:
        if not self._stream_active or not chunk:
            return
        self._stream_text.append(chunk)
        if self._stream_index is not None and self._stream_index < len(self._conversation_segments):
            self._conversation_segments[self._stream_index] += chunk
            self._refresh_conversation(scroll=True)

    # ------------------------------------------------------------------
    def finish_stream(self, final_text: str) -> None:
        content = final_text or "".join(self._stream_text)
        idx = self._stream_index
        if idx is not None and idx < len(self._conversation_segments):
            if content.strip():
                header = self._stream_header or ""
                segment = f"{header}{content}" if header else content
                self._conversation_segments[idx] = segment.rstrip()
            else:
                self._conversation_segments.pop(idx)
        self._stream_text = []
        self._stream_index = None
        self._stream_active = False
        self._stream_header = None
        if content:
            self._log_assistant_event(content)
        self._refresh_conversation(scroll=True)

    # ------------------------------------------------------------------
    def append_reasoning(self, chunk: str) -> None:
        if not chunk:
            return
        self._reasoning_chunks.append(chunk)
        if not self._reasoning_button or not self._reasoning_button.isChecked():
            self._reasoning_dirty = True
        self._update_reasoning_button()
        if self._reasoning_button and self._reasoning_button.isChecked():
            self._refresh_reasoning(scroll=True)

    # ------------------------------------------------------------------
    def finish_reasoning(self) -> None:
        self._refresh_reasoning(scroll=True)
        self._update_reasoning_button()


class _StatusPanelManager:
    """Controller keeping a singleton instance of the status panel."""

    def __init__(self) -> None:
        self._form: GepettoStatusForm | None = None
        self._stop_callback: Callable[[], None] | None = None

    # ------------------------------------------------------------------
    def ensure_shown(self) -> None:
        if self._form is None:
            self._form = GepettoStatusForm(self)
            if self._form is not None:
                try:
                    self._form.Show(STATUS_PANEL_CAPTION, options=ida_kernwin.PluginForm.WOPN_CREATE_ONLY)
                except Exception:
                    print(_("Could not show Gepetto Status panel."))
                    return

    # ------------------------------------------------------------------
    def form_closed(self) -> None:
        self._form = None

    # ------------------------------------------------------------------
    def on_form_ready(self) -> None:
        self.set_model(str(gepetto.config.model))
        if self._stop_callback:
            self._form.set_stop_callback(self._stop_callback)  # type: ignore[union-attr]
            self._form.reset_stop()  # type: ignore[union-attr]

        def _show_and_dock() -> None:
            if self._form is not None:
                ida_kernwin.display_widget(self._form.twidget(), _DEFAULT_DOCK_OPTIONS, None)
            orient = getattr(ida_kernwin, "DP_RIGHT", 0)
            szhint = getattr(ida_kernwin, "DP_SZHINT", 0)
            ida_kernwin.set_dock_pos(STATUS_PANEL_CAPTION, "IDA", orient | szhint)

        run_when_desktop_ready(_show_and_dock)

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
    def set_stop_callback(self, callback: Callable[[], None] | None) -> None:
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
            self._dispatch(lambda form: form.mark_cancelling())
            try:
                self._stop_callback()
            except Exception:
                self.mark_error(_("Failed to cancel request"))
                return
            self.set_status(_("Idle"), busy=False)
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
        self.set_status(_("Done"), busy=False)
        self.reset_stop()

    # ------------------------------------------------------------------
    def append_reasoning(self, chunk: str) -> None:
        self._dispatch(lambda form: form.append_reasoning(chunk))

    # ------------------------------------------------------------------
    def finish_reasoning(self) -> None:
        self._dispatch(lambda form: form.finish_reasoning())

    # ------------------------------------------------------------------
    def log_user(self, text: str) -> None:
        self._dispatch(lambda form: form.log_user(text))

    # ------------------------------------------------------------------
    def log(
        self,
        message: str,
        *,
        category: LogCategory = LogCategory.SYSTEM,
        level: LogLevel = LogLevel.INFO,
    ) -> None:
        self._dispatch(lambda form: form.append_log(message, False, category=category, level=level))

    # ------------------------------------------------------------------
    def log_request_started(self) -> str:
        message = _("Request to {model} sent...").format(model=str(gepetto.config.model))
        self.log(message, category=LogCategory.MODEL)
        self.set_status(_("Waiting for model..."), busy=True)
        return message

    # ------------------------------------------------------------------
    def log_request_finished(self, elapsed_seconds: float) -> str:
        message = _("{model} query finished in {time:.2f} seconds!").format(
            model=str(gepetto.config.model),
            time=elapsed_seconds,
        )
        self.log(message, category=LogCategory.MODEL, level=LogLevel.SUCCESS)
        self.set_status(_("Done"), busy=False)
        self.reset_stop()
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
