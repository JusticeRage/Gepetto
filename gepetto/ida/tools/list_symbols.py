import json

from gepetto.ida.utils.ida9_utils import enumerate_symbols

from gepetto.ida.tools.tools import add_result_to_messages



def handle_list_symbols_tc(tc, messages):
    """Handle a tool call to list symbols."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    prefix = args.get("prefix") or ""
    include_globals = bool(args.get("include_globals", False))

    try:
        result = list_symbols(prefix=prefix, include_globals=include_globals)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)


# -----------------------------------------------------------------------------


def list_symbols(prefix: str = "", include_globals: bool = False) -> dict:
    """Return names and EAs for functions and (optionally) global symbols.

    Enumeration is delegated to ida9_utils.enumerate_symbols(), which runs on the
    IDA main thread and returns a unified schema: {"name", "ea", "kind"}.
    """
    try:
        syms = enumerate_symbols()
        pref = prefix or ""
        if pref:
            syms = [s for s in syms if (s.get("name") or "").startswith(pref)]
        if not include_globals:
            syms = [s for s in syms if s.get("kind") == "function"]
        # Format result consistently: EAs are integers, include 'kind'
        return {"ok": True, "symbols": [{"name": s["name"], "ea": int(s["ea"]), "kind": s["kind"]} for s in syms]}
    except Exception as e:
        return {"ok": False, "symbols": [], "error": str(e)}
