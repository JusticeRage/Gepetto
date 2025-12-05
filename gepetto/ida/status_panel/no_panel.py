from typing import Callable, Optional
from .panel_interface import StatusPanel, LogCategory, LogLevel


class NoStatusPanel(StatusPanel):
    def __init__(self) -> None:
        self._stop_callback: Optional[Callable[[], None]] = None

    def ensure_shown(self) -> None:
        pass

    def form_closed(self) -> None:
        pass

    def on_form_ready(self) -> None:
        pass

    def set_model(self, model_name: str) -> None:
        pass

    def set_status(self, text: str, *, busy: bool = False, error: bool = False) -> None:
        pass

    def set_stop_callback(self, callback: Optional[Callable[[], None]]) -> None:
        self._stop_callback = callback

    def reset_stop(self) -> None:
        pass

    def has_stop_callback(self) -> bool:
        return self._stop_callback is not None

    def request_stop(self) -> None:
        pass

    def start_stream(self) -> None:
        pass

    def append_stream(self, chunk: str) -> None:
        pass

    def finish_stream(self, final_text: str) -> None:
        pass

    def append_reasoning(self, chunk: str) -> None:
        pass

    def finish_reasoning(self) -> None:
        pass

    def log(self, message: str, *, category: LogCategory = LogCategory.SYSTEM, level: LogLevel = LogLevel.INFO) -> None:
        pass

    def log_user(self, text: str) -> None:
        pass

    def log_request_started(self) -> str:
        pass

    def log_request_finished(self, elapsed_seconds: float) -> str:
        pass

    def mark_error(self, message: str) -> None:
        pass

    def clear_log(self) -> None:
        pass

    def close(self) -> None:
        pass
