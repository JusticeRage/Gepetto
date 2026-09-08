"""An input that is as tall as what has been typed into it.

The prompt used to be a QLineEdit, which is one line and stays one line. That
is not only cramped: a line edit has no newline at all, so a prompt with a
paragraph in it, or a pasted struct definition, could not be written -- only
pasted in as a single unreadable run.

So: a text area that starts at one line, grows to a few as the text does, and
scrolls after that; Enter still sends, Shift-Enter makes a new line; and for a
prompt too long for even that, a button that opens the same text in a window
that can be resized.
"""

from gepetto.ida.status_panel.panel_controls import register_prompt_button
from gepetto.ida.status_panel.prompt_sizing import visible_height
from gepetto.ida.qt import QShortcut, QtCore, QtGui, QtWidgets

import gepetto.config

_ = gepetto.config._

def _standard_icon(widget, name):
    """A themed icon by name, or a null icon if this style has no such thing."""
    style = widget.style()
    pixmaps = getattr(QtWidgets.QStyle, "StandardPixmap", QtWidgets.QStyle)
    enum_value = getattr(pixmaps, name, None)
    if enum_value is None:
        return QtGui.QIcon()
    return style.standardIcon(enum_value)


class PromptInput(QtWidgets.QPlainTextEdit):
    """The prompt box, sized to its contents."""

    def __init__(self, on_submit, parent=None):
        super().__init__(parent)
        self._on_submit = on_submit
        self._minimum_height = 0
        # Short enough to fit the one line the box starts as. The longer
        # version wrapped, and a placeholder that does not fit is worse than a
        # placeholder that says less.
        self.setPlaceholderText(_("Type a prompt and press Enter…"))
        self.setToolTip(_("Enter sends. Shift+Enter starts a new line."))
        self.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                           QtWidgets.QSizePolicy.Fixed)
        self.setTabChangesFocus(True)
        self.document().documentLayout().documentSizeChanged.connect(
            lambda _size: self._fit_to_content())
        self._fit_to_content()

    # --- behaving like the line edit it replaced ------------------------------
    #
    # The panel already says .text() and .clear(); there is no reason for it to
    # learn a second vocabulary because the widget underneath changed.

    def text(self):
        return self.toPlainText()

    def setText(self, value):
        self.setPlainText(value or "")

    # --- growing --------------------------------------------------------------

    def _line_height(self):
        return QtGui.QFontMetrics(self.font()).lineSpacing()

    def _chrome(self):
        """Everything that is not text: frame, document margin, padding."""
        margins = self.contentsMargins()
        return (int(self.document().documentMargin()) * 2
                + self.frameWidth() * 2
                + margins.top() + margins.bottom() + 2)

    def set_minimum_height(self, height):
        """Never shorter than this, so it lines up with what sits beside it."""
        self._minimum_height = int(height or 0)
        self._fit_to_content()

    def _fit_to_content(self):
        height, scrolls = visible_height(
            self.document().size().height(),
            self._line_height(),
            self._chrome(),
            self._minimum_height,
        )
        if height != self.height():
            self.setFixedHeight(height)
        # Only once it has stopped growing does a scrollbar earn its place.
        self.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded if scrolls
            else QtCore.Qt.ScrollBarAlwaysOff)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Wrapping changes with the width, and so does the number of lines.
        self._fit_to_content()

    # --- sending --------------------------------------------------------------

    def keyPressEvent(self, event):
        if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
            if event.modifiers() & (QtCore.Qt.ShiftModifier
                                    | QtCore.Qt.ControlModifier
                                    | QtCore.Qt.AltModifier
                                    | QtCore.Qt.MetaModifier):
                super().keyPressEvent(event)
                return
            self.submit()
            return
        super().keyPressEvent(event)

    def submit(self):
        if callable(self._on_submit):
            self._on_submit()


class PromptWindow(QtWidgets.QDialog):
    """The same prompt, in something that can be resized."""

    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_("Gepetto prompt"))
        self.resize(720, 420)
        self.setSizeGripEnabled(True)

        layout = QtWidgets.QVBoxLayout(self)
        self.editor = QtWidgets.QPlainTextEdit()
        self.editor.setPlainText(text or "")
        self.editor.moveCursor(QtGui.QTextCursor.End)
        layout.addWidget(self.editor, 1)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        ok = buttons.button(QtWidgets.QDialogButtonBox.Ok)
        ok.setText(_("Use this"))
        # Deliberately not "Send": what comes back lands in the prompt box, so
        # a long prompt can still be read once more before it goes.
        ok.setToolTip(_("Put this back in the prompt box (Ctrl+Enter)"))
        buttons.button(QtWidgets.QDialogButtonBox.Cancel).setText(_("Cancel"))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        for sequence in ("Ctrl+Return", "Ctrl+Enter"):
            QShortcut(QtGui.QKeySequence(sequence), self, self.accept)

    def text(self):
        return self.editor.toPlainText()


@register_prompt_button
def expand_button(prompt_input, parent=None):
    """The button that opens the prompt in a window of its own."""
    button = QtWidgets.QToolButton(parent)
    icon = _standard_icon(button, "SP_TitleBarMaxButton")
    if icon.isNull():
        button.setText("[ ]")
    else:
        button.setIcon(icon)
    button.setToolTip(_("Write this prompt in a larger window"))
    button.setAutoRaise(True)

    def open_window():
        window = PromptWindow(prompt_input.text(), prompt_input.window())
        if window.exec() if hasattr(window, "exec") else window.exec_():
            prompt_input.setText(window.text())
            prompt_input.setFocus()
            prompt_input.moveCursor(QtGui.QTextCursor.End)

    button.clicked.connect(open_window)
    return button


def align_row(prompt_input, *buttons):
    """Make the buttons and the empty prompt box the same height.

    A text area sizes itself from its contents and a push button from its
    label, so left alone they disagree by a few pixels and the row looks
    assembled rather than designed. The buttons decide, because their height is
    the one the platform chose.
    """
    heights = [button.sizeHint().height() for button in buttons if button]
    if not heights:
        return
    height = max(heights)
    prompt_input.set_minimum_height(height)
    for button in buttons:
        if button is None:
            continue
        button.setFixedHeight(height)
        # The expand button has no label, so without this it is a sliver.
        if isinstance(button, QtWidgets.QToolButton):
            button.setFixedWidth(height)
