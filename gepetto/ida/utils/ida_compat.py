import idaapi
import ida_kernwin
import re
from functools import wraps

def get_ida_version():
    """
    Returns the IDA version as a tuple of (major, minor).
    Robust to versions like '7.7.0.220118'.
    """
    version_str = idaapi.get_kernel_version()
    parts = re.findall(r'\d+', version_str or '')
    major = int(parts[0]) if len(parts) >= 1 else 0
    minor = int(parts[1]) if len(parts) >= 2 else 0
    return major, minor

def is_ida7():
    major, _ = get_ida_version()
    return major == 7

def is_ida8():
    major, _ = get_ida_version()
    return major == 8

def is_ida9():
    major, _ = get_ida_version()
    return major >= 9

def is_ida9_or_greater():
    major, minor = get_ida_version()
    return major > 9 or (major == 9 and minor >= 2)

def has_hexrays():
    try:
        import ida_hexrays  # noqa: F401
        return ida_hexrays.init_hexrays_plugin()
    except Exception:
        return False

def has_execute_sync():
    return hasattr(ida_kernwin, 'execute_sync') or hasattr(idaapi, 'execute_sync')

def _execute_sync(callable_, flags=None):
    """
    Execute callable_ on the main thread, using whichever API is available.
    """
    if flags is None:
        flags = getattr(ida_kernwin, 'MFF_WRITE', getattr(idaapi, 'MFF_WRITE', 1))
    fn = getattr(ida_kernwin, 'execute_sync', None)
    if callable(fn):
        return fn(callable_, flags)
    fn2 = getattr(idaapi, 'execute_sync', None)
    if callable(fn2):
        return fn2(callable_, flags)
    # Last resort: call directly (assumed already safe)
    return callable_()

def _is_main_thread():
    """
    Return True if current thread is IDA main thread; on older IDA versions where
    ida_kernwin.is_main_thread() is unavailable, default to False so we schedule via execute_sync.
    """
    fn = getattr(ida_kernwin, 'is_main_thread', None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception:
            pass
    return False

def run_on_main_thread(func):
    """
    Decorator to ensure a function executes on IDA's main thread across versions.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        def task():
            return func(*args, **kwargs)
        if _is_main_thread():
            return task()
        return _execute_sync(task, getattr(ida_kernwin, 'MFF_WRITE', getattr(idaapi, 'MFF_WRITE', 1)))
    return wrapper

def is_ida_ge(major: int, minor: int) -> bool:
    cur_major, cur_minor = get_ida_version()
    return (cur_major, cur_minor) >= (major, minor)

def qt_binding() -> str:
    # PySide6 is 9.2+ exclusive
    return 'PySide6' if is_ida_ge(9, 2) else 'PyQt5'
