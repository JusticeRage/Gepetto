import json

import ida_bytes
import idaapi
import ida_segment

from gepetto.ida.utils.function_helpers import parse_ea, get_ptr_size, get_endianness
from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)
from gepetto.ida.utils.thread_helpers import ida_read


# -----------------------------------------------------------------------------
# Tool call handler
# -----------------------------------------------------------------------------

def handle_get_bytes_tc(tc, messages):
    """Handle tool call for get_bytes."""
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    ea = args.get("ea")
    size = args.get("size", 0x20)
    auto_dereference = args.get("auto_dereference", True)

    try:
        ea_i = parse_ea(ea)
        size_i = int(size)
        auto_deref_b = bool(auto_dereference)

        data = get_bytes(ea_i, size_i, auto_dereference=auto_deref_b)
        payload = tool_result_payload(data)
    except Exception as ex:
        payload = tool_error_payload(
            str(ex),
            ea=ea if isinstance(ea, int) else None,
            size=size if isinstance(size, int) else None,
            auto_dereference=auto_dereference if isinstance(auto_dereference, bool) else None,
        )

    add_result_to_messages(messages, tc, payload)


@ida_read
def _read_bytes(ea: int, size: int) -> bytes:
    return ida_bytes.get_bytes(ea, size) or b""


# -----------------------------------------------------------------------------
# Formatting / decoding helpers
# -----------------------------------------------------------------------------

def _format_bytes(bs: bytes) -> str:
    return " ".join(f"0x{b:02X}" for b in bs)


def _is_printable_byte(b: int) -> bool:
    # Consider \t, \n, \r printable (in addition to ASCII printable range).
    return b in (9, 10, 13) or 32 <= b <= 126


def _decode_if_printable(
        bs: bytes,
        *,
        max_len: int | None = None,
        min_printable_ratio: float = 0.85,
) -> dict[str, str] | None:
    """
    If the bytes look like mostly-printable text, return:
      {"encoding": "...", "text": "..."}
    Always caps recognition to max_len (defaults to len(bs)).
    """
    if not bs:
        return None

    if max_len is None:
        max_len = len(bs)
    if max_len <= 0:
        return None

    capped = bs[:max_len]

    nul = capped.find(b"\x00")
    candidate = capped if nul < 0 else capped[:nul]
    if not candidate:
        return None

    printable = sum(1 for x in candidate if _is_printable_byte(x))
    ratio = printable / max(1, len(candidate))
    if ratio < min_printable_ratio:
        return None

    try:
        return {"encoding": "utf-8", "text": candidate.decode("utf-8")}
    except UnicodeDecodeError:
        return {"encoding": "latin-1", "text": candidate.decode("latin-1")}

# -----------------------------------------------------------------------------
# Pointer / offset detection
# -----------------------------------------------------------------------------

@ida_read
def _read_ptr_value(ea: int) -> int:
    ps = get_ptr_size()
    if ps == 8:
        return ida_bytes.get_qword(ea)
    if ps == 4:
        return ida_bytes.get_dword(ea)
    return ida_bytes.get_word(ea)

@ida_read
def _looks_like_pointer_value(ptr: int) -> bool:
    if ptr in (0, idaapi.BADADDR):
        return False

    try:
        inf = idaapi.get_inf_structure()
        if ptr < inf.min_ea or ptr >= inf.max_ea:
            return False
    except AttributeError:  # IDA 9.x API
        import ida_ida
        if ptr < ida_ida.inf_get_min_ea() or ptr >= ida_ida.inf_get_max_ea():
            return False

    if ida_segment.getseg(ptr) is None:
        return False

    if not ida_bytes.is_loaded(ptr):
        return False

    return True

@ida_read
def _ida_offset_target(ea: int) -> int | None:
    """
    If IDA has a data item at EA marked as an offset, return the offset target.
    """
    head = ida_bytes.get_item_head(ea)
    if head == idaapi.BADADDR:
        return None

    f = ida_bytes.get_full_flags(head)

    # For data items, operand 0 is the relevant "offsetness" in practice.
    if ida_bytes.is_data(f) and ida_bytes.is_off0(f):
        ptr = _read_ptr_value(head)
        return ptr if ptr not in (0, idaapi.BADADDR) else None

    return None


def _heuristic_pointer_target(ea: int, bs_at_ea: bytes) -> int | None:
    """
    Fallback heuristic: interpret the first pointer-sized bytes as an EA and
    accept if it lands in a loaded segment.
    """
    ps = get_ptr_size()
    if len(bs_at_ea) < ps:
        return None

    ptr = int.from_bytes(bs_at_ea[:ps], get_endianness(), signed=False)

    return ptr if _looks_like_pointer_value(ptr) else None


def _choose_deref_target(ea: int, bs_at_ea: bytes) -> tuple[int | None, str | None]:
    """
    Returns (target_ea, reason) or (None, None).
    reason is "ida_offset" or "heuristic".
    """
    ida_ptr = _ida_offset_target(ea)
    if ida_ptr is not None and _looks_like_pointer_value(ida_ptr):
        return ida_ptr, "ida_offset"

    heur_ptr = _heuristic_pointer_target(ea, bs_at_ea)
    if heur_ptr is not None:
        return heur_ptr, "heuristic"

    return None, None

# -----------------------------------------------------------------------------
# Public tool function
# -----------------------------------------------------------------------------

def get_bytes(ea: int, size: int = 0x20, *, auto_dereference: bool = True) -> dict[str, object]:
    """
    Return bytes starting at EA.

    If auto_dereference is True and EA looks like a pointer/offset, the returned
    primary "bytes"/"decoded" correspond to the pointed-to data, and the original
    bytes at EA are preserved under "pointer_bytes"/"pointer_decoded".
    """
    if size <= 0:
        raise ValueError("size must be a positive integer")

    bs_at_ea = _read_bytes(ea, size)

    # Default: primary view is the requested EA.
    primary_ea = ea
    primary_bs = bs_at_ea
    primary_reason = None
    pointer_info: dict[str, object] | None = None

    if auto_dereference:
        target, reason = _choose_deref_target(ea, bs_at_ea)
        if target is not None and target != ea:
            deref_bs = _read_bytes(target, size)

            # Primary becomes dereferenced data.
            primary_ea = target
            primary_bs = deref_bs
            primary_reason = reason

            # Preserve pointer bytes (what was at the requested EA).
            pointer_info = {
                "pointer_ea": ea,
                "pointer_size": get_ptr_size(),
                "pointer_bytes": _format_bytes(bs_at_ea),
            }
            pointer_dec = _decode_if_printable(bs_at_ea, max_len=size)
            if pointer_dec:
                pointer_info["pointer_decoded"] = pointer_dec

    out: dict[str, object] = {
        # The EA we actually returned bytes for (may differ if dereferenced)
        "ea": primary_ea,
        "size": size,
        "bytes": _format_bytes(primary_bs),
    }

    dec = _decode_if_printable(primary_bs, max_len=size)
    if dec:
        out["decoded"] = dec

    if pointer_info is not None:
        out["auto_dereference"] = {
            "enabled": True,
            "reason": primary_reason,     # "ida_offset" or "heuristic"
            "requested_ea": ea,
            "returned_ea": primary_ea,
            **pointer_info,
        }
    else:
        out["auto_dereference"] = {
            "enabled": bool(auto_dereference),
            "applied": False,
            "requested_ea": ea,
        }

    return out
