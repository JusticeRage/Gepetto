import json
import re

import ida_typeinf
import idc

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


from gepetto.ida.utils.thread_helpers import ida_write


_TYPE_NAME_PATTERNS = [
    re.compile(r"\btypedef\s+.*?\b([A-Za-z_]\w*)\s*;", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bstruct\s+([A-Za-z_]\w*)\b", re.IGNORECASE),
    re.compile(r"\bunion\s+([A-Za-z_]\w*)\b", re.IGNORECASE),
    re.compile(r"\benum\s+([A-Za-z_]\w*)\b", re.IGNORECASE),
    re.compile(r"\bclass\s+([A-Za-z_]\w*)\b", re.IGNORECASE),
    re.compile(r"\b([A-Za-z_]\w*)\s*\(", re.IGNORECASE),
]


def handle_declare_c_type_tc(tc, messages):
    """Handle a tool call to declare C types."""
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}

    c_decl = args.get("c_declaration")

    try:
        data = declare_c_type(c_declaration=c_decl)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(str(ex), c_declaration=c_decl)

    add_result_to_messages(messages, tc, payload)


# -----------------------------------------------------------------------------


@ida_write
def _apply_declarations(decl_text: str) -> dict[str, object]:
    til = ida_typeinf.get_idati()
    if til is None:
        raise RuntimeError("Local type library is unavailable.")

    errors = ida_typeinf.parse_decls(til, decl_text, None, ida_typeinf.PT_SIL)
    if errors:
        fallback_errors = idc.parse_decls(decl_text, ida_typeinf.PT_SIL)
        if fallback_errors:
            raise RuntimeError(f"Failed to parse declarations ({fallback_errors} errors).")

    candidates = _extract_type_candidates(decl_text)
    chosen = ""
    for candidate in candidates:
        try:
            if ida_typeinf.get_named_type(til, candidate, ida_typeinf.NTF_TYPE):
                chosen = candidate
                break
        except Exception:
            continue
    if not chosen and candidates:
        chosen = candidates[-1]

    return {"success": True, "type_name": chosen}


def _extract_type_candidates(text: str) -> list[str]:
    """Return best-effort candidate names declared by the snippet."""
    candidates: list[str] = []
    for pattern in _TYPE_NAME_PATTERNS:
        for match in pattern.finditer(text):
            candidate = match.group(1)
            if candidate and candidate not in candidates:
                candidates.append(candidate)
    return candidates


def declare_c_type(c_declaration: str | None) -> dict[str, object]:
    """Parse and register one or more C declarations."""
    if not c_declaration or not c_declaration.strip():
        raise ValueError("c_declaration must be a non-empty string")

    decl_text = c_declaration.strip()
    return _apply_declarations(decl_text)

