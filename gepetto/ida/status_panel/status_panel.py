from .panel_interface import StatusPanel, LogCategory, LogLevel
from .no_panel import NoStatusPanel

_panel: StatusPanel | None = None


def get_status_panel() -> StatusPanel:
    global _panel
    if _panel is not None:
        return _panel

    # Try to build a Qt one; fall back to null if anything goes wrong.
    try:
        # TODO: depending on idaapi.IDA_SDK_VERSION, show the Qt5 panel or Qt6 one.
        from .qt_panel import _StatusPanelManager
        _panel = _StatusPanelManager()
    except Exception:
        _panel = NoStatusPanel()

    return _panel
