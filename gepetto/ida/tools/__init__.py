"""Expose IDA tool modules for convenient attribute access."""

# Import tool handler modules so ``gepetto.ida.tools.<module>`` works even if
# only the package is imported. This mirrors the legacy behaviour relied upon
# by the CLI and external integrations.

from . import declare_c_type  # noqa: F401
from . import decompile_function  # noqa: F401
from . import get_bytes  # noqa: F401
from . import get_current_function  # noqa: F401
from . import get_disasm  # noqa: F401
from . import get_ea  # noqa: F401
from . import get_screen_ea  # noqa: F401
from . import get_struct  # noqa: F401
from . import get_xrefs  # noqa: F401
from . import list_functions  # noqa: F401
from . import list_imports  # noqa: F401
from . import list_symbols  # noqa: F401
from . import refresh_view  # noqa: F401
from . import rename_function  # noqa: F401
from . import rename_lvar  # noqa: F401
from . import search  # noqa: F401
from . import set_comment  # noqa: F401
from . import to_hex  # noqa: F401
from . import run_python  # noqa: F401
from . import rename_global  # noqa: F401

__all__ = [
    "declare_c_type",
    "decompile_function",
    "get_bytes",
    "get_current_function",
    "get_disasm",
    "get_ea",
    "get_screen_ea",
    "get_struct",
    "get_xrefs",
    "list_functions",
    "list_imports",
    "list_symbols",
    "refresh_view",
    "rename_function",
    "rename_lvar",
    "search",
    "set_comment",
    "to_hex",
    "run_python",
    "rename_global.py",
]
