import json

import ida_bytes
import ida_search
import ida_kernwin
import ida_idaapi

from gepetto.ida.tools.tools import add_result_to_messages


def handle_search_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    text = args.get("text")
    hex_pattern = args.get("hex")
    case_sensitive = bool(args.get("case_sensitive", False))

    try:
        result = search(text=text, hex=hex_pattern, case_sensitive=case_sensitive)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}

    add_result_to_messages(messages, tc, result)


def search(text: str | None = None, hex: str | None = None, case_sensitive: bool = False) -> dict:
    out: dict = {"ok": False, "eas": [], "error": None}

    if not text and not hex:
        out["error"] = "Either text or hex must be provided"
        return out

    def _do():
        try:
            matches: list[int] = []
            if text:
                cmp_text = text if case_sensitive else text.lower()
                try:
                    flags = getattr(ida_bytes, "STRFIND_CASE", 0) if case_sensitive else 0
                    ea = ida_bytes.find_strlit(0, cmp_text, flags)
                    while ea != ida_idaapi.BADADDR:
                        matches.append(int(ea))
                        ea = ida_bytes.find_strlit(ea + 1, cmp_text, flags)
                except Exception:
                    f = ida_search.SEARCH_DOWN
                    if case_sensitive:
                        f |= ida_search.SEARCH_CASE
                    ea = ida_search.find_text(0, 1, 1, text, f)
                    while ea != ida_idaapi.BADADDR:
                        matches.append(int(ea))
                        ea = ida_search.find_text(ea + 1, 1, 1, text, f)

            if hex:
                f = ida_search.SEARCH_DOWN
                ea = ida_search.find_binary(0, ida_idaapi.BADADDR, hex, 16, f)
                while ea != ida_idaapi.BADADDR:
                    matches.append(int(ea))
                    ea = ida_search.find_binary(ea + 1, ida_idaapi.BADADDR, hex, 16, f)

            out["eas"] = matches
            out["ok"] = True
            return 1
        except Exception as e:
            out["error"] = str(e)
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out
