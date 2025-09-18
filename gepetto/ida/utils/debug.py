import logging
import os
import sys
import traceback


def _ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _default_log_path() -> str:
    # Prefer IDA _dev dir on Windows; otherwise fall back to CWD
    appdata = os.environ.get("APPDATA", "")
    base = os.path.join(appdata, "Hex-Rays", "_dev", "Gepetto") if appdata else os.getcwd()
    _ensure_dir(base)
    return os.path.join(base, "gepetto_debug.log")


from typing import Optional


def configure_logging(level: int = logging.DEBUG, logfile: Optional[str] = None) -> logging.Logger:
    """Configure a dedicated logger for Gepetto with a rotating file handler.

    Safe to call multiple times; subsequent calls will be ignored if already set.
    """
    logger = logging.getLogger("gepetto")
    if getattr(logger, "_gepetto_configured", False):
        return logger

    logger.setLevel(level)

    # Stream to IDA Output window via stdout/stderr
    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setLevel(level)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)

    try:
        from logging.handlers import RotatingFileHandler

        logfile = logfile or _default_log_path()
        fh = RotatingFileHandler(logfile, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(fh)
    except Exception:
        # File logging is optional; continue without it
        pass

    logger._gepetto_configured = True  # type: ignore[attr-defined]
    return logger


def install_sys_excepthook(logger: logging.Logger | None = None) -> None:
    """Install a sys.excepthook that mirrors uncaught exceptions to IDA's Output window.

    IDA sometimes shows a generic "Warning" box for unhandled exceptions. This hook ensures the
    full traceback is printed to stdout/stderr (visible in the Output window) and to our logfile.
    """
    logger = logger or configure_logging()

    def _hook(exc_type, exc, tb):
        tb_text = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            import ida_kernwin  # Imported lazily to avoid IDA import at module load

            ida_kernwin.msg("\n[Gepetto] Unhandled exception:\n%s\n" % tb_text)
        except Exception:
            pass
        try:
            logger.error("Unhandled exception", exc_info=(exc_type, exc, tb))
        except Exception:
            pass
        # Delegate to default hook for any additional behavior
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook


def trace_errors(context: str = ""):
    """Decorator that captures exceptions, logs a traceback, and surfaces a user-friendly hint.

    - Prints the full traceback to the Output window and the logfile.
    - Shows a small warning dialog that points the user at the Output window/logfile.
    - Respects env/config `GEPETTO_DEBUG_RAISE=1` to re-raise after logging.
    """

    def _decorator(fn):
        import functools

        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:  # noqa: BLE001
                logger = configure_logging()
                tb_text = traceback.format_exc()
                try:
                    import ida_kernwin

                    ida_kernwin.msg(
                        f"\n[Gepetto] Exception in {context or fn.__qualname__}: {e}\n{tb_text}\n"
                    )
                except Exception:
                    pass
                try:
                    logger.exception("Exception in %s", context or fn.__qualname__)
                except Exception:
                    pass
                try:
                    import gepetto.config as _cfg
                    _ = _cfg._
                except Exception:
                    _ = lambda s: s  # noqa: E731
                try:
                    import ida_kernwin

                    ida_kernwin.warning(
                        _(
                            "{ctx} failed with an exception. See 'View → Output window' and gepetto_debug.log for a traceback."
                        ).format(ctx=context or fn.__qualname__)
                    )
                except Exception:
                    pass
                if os.environ.get("GEPETTO_DEBUG_RAISE", "0") in {"1", "true", "True"}:
                    raise
                # For IDA action handlers returning int, a safe default is to return 1 (handled)
                return 1

        return _wrapped

    return _decorator


def enable_debug_mode_from_config():
    """Enable debug logging and stricter warnings/hooks based on config/env flags.

    - `GEPETTO_DEBUG=1` → enable logging + sys.excepthook
    - `PYTHONWARNINGS` environment variable is respected; otherwise if `GEPETTO_WARNINGS_AS_ERRORS=1`,
       convert warnings to errors to surface issues early.
    """
    try:
        import gepetto.config as _cfg
        debug_flag = _cfg.get_config("Gepetto", "DEBUG", environment_variable="GEPETTO_DEBUG", default="0")
    except Exception:
        debug_flag = os.environ.get("GEPETTO_DEBUG", "0")

    if str(debug_flag).lower() in {"1", "true", "yes", "on"}:
        logger = configure_logging()
        install_sys_excepthook(logger)

    # Warnings-as-errors (optional)
    try:
        import warnings

        if os.environ.get("PYTHONWARNINGS") is None:
            if os.environ.get("GEPETTO_WARNINGS_AS_ERRORS", "0") in {"1", "true", "True"}:
                warnings.simplefilter("error")
    except Exception:
        pass
