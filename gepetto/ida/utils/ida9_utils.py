"""
IDA 9.x utility functions for robust plugin operation.

This module provides thread-safe, headless-tolerant utilities for common
IDA operations with proper error handling and fallback mechanisms.
"""
import gepetto.config
_ = gepetto.config._

# Be import-safe outside IDA: guard imports
try:
    import idaapi  # type: ignore
except Exception:
    idaapi = None
try:
    import ida_kernwin  # type: ignore
except Exception:
    ida_kernwin = None
try:
    import ida_hexrays  # type: ignore
except Exception:
    ida_hexrays = None
try:
    import ida_funcs  # type: ignore
except Exception:
    ida_funcs = None
try:
    import ida_typeinf  # type: ignore
except Exception:
    ida_typeinf = None
try:
    import idc  # type: ignore
except Exception:
    idc = None

# Fallback for BADADDR outside IDA
BADADDR = idaapi.BADADDR if idaapi else -1

# Module-level plugin state for tracking last known EA
plugin_state = {"last_ea": None}


def run_on_main_thread(fn, write=False):
    """
    Execute a function on the main thread using appropriate synchronization.

    Always traps exceptions inside the scheduled callable to avoid
    execute_sync() surfacing a low-level "exception set" error.

    Args:
        fn: Function to execute
        write: If True, use MFF_WRITE for database modifications, otherwise MFF_READ

    Returns:
        Result of the function execution (return value of fn), or raises RuntimeError on failure
    """
    if ida_kernwin and idaapi:
        # Prefer ida_kernwin's flag constants on IDA 9.x
        try:
            sync_flag = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
        except Exception:
            # Fallback to idaapi for older bindings
            sync_flag = getattr(idaapi, 'MFF_WRITE', 1 if write else 0)
        slot = {}
        def _runner():
            try:
                slot["result"] = fn()
                slot["ok"] = True
            except Exception as e:
                slot["ok"] = False
                slot["error"] = str(e)
            return 1
        ida_kernwin.execute_sync(_runner, sync_flag)
        if not slot.get("ok", False):
            # Unify error text for upstream callers
            err = slot.get("error") or "Failed to execute on main thread"
            raise RuntimeError(err)
        return slot.get("result")
    # Outside IDA: best effort fallback to direct call
    return fn()


def parse_ea(ea_input):
    """
    Parse EA from various input formats (int, hex string, decimal string).
    
    Args:
        ea_input: EA as int or string ("0x1234", "1234", "1234h")
        
    Returns:
        int: Parsed effective address
        
    Raises:
        ValueError: If input cannot be parsed as valid EA
    """
    if ea_input is None:
        raise ValueError(_("No EA provided"))
    if isinstance(ea_input, int):
        return ea_input
    if isinstance(ea_input, str):
        s = ea_input.strip()
        if not s:
            raise ValueError(_("Empty EA string"))
        # Handle 'h' suffix (hex)
        if s.lower().endswith('h'):
            s = "0x" + s[:-1]
        try:
            return int(s, 0)  # Auto-detect base (0x for hex, else decimal)
        except ValueError:
            raise ValueError(_("Invalid EA format: {value}").format(value=repr(ea_input)))
    raise ValueError(_("Unsupported EA type: {type_name}").format(type_name=type(ea_input).__name__))


def ea_to_hex(ea):
    """
    Convert EA to hex string representation.
    
    Args:
        ea: Effective address as integer
        
    Returns:
        str: Hex representation ("0x1234") or "BADADDR" for invalid EA
    """
    if (idaapi and ea == idaapi.BADADDR) or (not idaapi and ea == BADADDR):
        return "BADADDR"
    return f"0x{ea:x}"


def safe_get_screen_ea():
    """
    Safely get current screen EA with fallbacks for headless mode.
    
    Returns:
        int: Current effective address or BADADDR if unavailable
    """
    # Try primary: on main thread if IDA is present
    if ida_kernwin and idaapi:
        try:
            ea = run_on_main_thread(lambda: ida_kernwin.get_screen_ea(), write=False) or BADADDR
            if ea != BADADDR:
                return int(ea)
        except Exception:
            pass

    # Try alternative (IDAPython convenience) if present
    if idc:
        try:
            ea = idc.get_screen_ea()
            if idaapi:
                if ea != idaapi.BADADDR:
                    return int(ea)
            else:
                if ea != BADADDR:
                    return int(ea)
        except Exception:
            pass
    
    # Fallback to last known EA
    last = plugin_state.get("last_ea")
    if last is not None and last != BADADDR:
        return int(last)
    
    return BADADDR


def safe_get_current_address():
    """
    Thin wrapper around safe_get_screen_ea for compatibility.
    
    Returns:
        int: Current effective address or BADADDR if unavailable
    """
    return safe_get_screen_ea()


def touch_last_ea(ea: int):
    """
    Store the last valid EA for fallback purposes.
    
    Args:
        ea: Effective address to store (ignored if BADADDR)
    """
    if ea is None:
        return
    if (idaapi and ea != idaapi.BADADDR) or (not idaapi and ea != BADADDR):
        plugin_state["last_ea"] = int(ea)


def hexrays_available():
    """
    Check if Hex-Rays decompiler is available and initialized.
    
    Returns:
        bool: True if Hex-Rays is available, False otherwise
    """
    try:
        if not ida_hexrays:
            return False
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def decompile_func(func_ea: int):
    """
    Safely decompile a function with proper error handling.
    
    Args:
        func_ea: Function effective address
        
    Returns:
        cfunc_t: Decompiled function object
        
    Raises:
        RuntimeError: If Hex-Rays unavailable or decompilation fails
    """
    if not hexrays_available() or not ida_funcs or not idaapi:
        raise RuntimeError("Hex-Rays not available: install/enable the Hex-Rays Decompiler.")
    
    try:
        # Check if function exists
        func = ida_funcs.get_func(func_ea)
        if not func:
            return ida_hexrays.decompile(func_ea)
            # raise RuntimeError(f"EA {ea_to_hex(func_ea)} is not inside a function.")
        
        # Attempt decompilation
        err = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(func_ea, err, ida_hexrays.DECOMP_WARNINGS)
        
        if not cfunc:
            msg = f"Decompilation failed at {ea_to_hex(func_ea)}"
            if getattr(err, "str", None):
                msg += f": {err.str}"
            errea = getattr(err, "errea", BADADDR)
            if (idaapi and errea != idaapi.BADADDR) or (not idaapi and errea != BADADDR):
                msg += f" (address: {ea_to_hex(errea)})"
            raise RuntimeError(msg)
            
        return cfunc
        
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Decompilation error: {str(e)}")


def get_candidates_for_name(target_name: str, max_candidates: int = 10):
    """
    Find candidate names similar to the target name for suggestion purposes.
    
    Args:
        target_name: Name to find candidates for
        max_candidates: Maximum number of candidates to return
        
    Returns:
        list: List of dicts with 'name' and 'ea' keys for similar names
    """
    candidates = []
    target_lower = target_name.lower()
    
    def _do():
        nonlocal candidates
        try:
            import idautils
            # Search through all names for substring matches
            for addr, name in idautils.Names():
                if target_lower in name.lower() and name != target_name:
                    candidates.append({"name": name, "ea": ea_to_hex(addr)})
                    if len(candidates) >= max_candidates:
                        break
        except Exception:
            pass
        return 1
    
    run_on_main_thread(_do, write=False)
    return candidates


def parse_type_declaration(type_decl: str):
    """
    Parse a type declaration string into a tinfo_t object using IDA 9.x APIs.
    
    Args:
        type_decl: Type declaration string (e.g., "int *", "char[32]")
        
    Returns:
        tinfo_t: Parsed type information
        
    Raises:
        ValueError: If type cannot be parsed
    """
    if not type_decl or not type_decl.strip():
        raise ValueError(_("Empty type declaration"))
    
    type_decl = type_decl.strip()
    tif = ida_typeinf.tinfo_t()
    
    # Try direct construction first
    try:
        tif = ida_typeinf.tinfo_t(type_decl)
        if tif.is_correct():
            return tif
    except Exception:
        pass
    
    # Fallback to parse_decl - ensure semicolon for proper parsing
    decl_str = type_decl if type_decl.endswith(';') else type_decl + ';'
    
    if ida_typeinf.parse_decl(tif, None, decl_str, ida_typeinf.PT_SIL):
        if tif.is_correct():
            return tif
    
    raise ValueError(_("Failed to parse type declaration: {type_decl}").format(type_decl=type_decl))


def validate_function_ea(ea: int):
    """
    Validate that an EA points to a valid function.
    
    Args:
        ea: Effective address to validate
        
    Returns:
        func_t: Function object if valid
        
    Raises:
        ValueError: If EA is not inside a function
    """
    func = ida_funcs.get_func(ea)
    if not func:
        raise ValueError(_("EA {ea} is not inside a function.").format(ea=ea_to_hex(ea)))
    return func

def enumerate_symbols():
    """
    Enumerate all named symbols (functions and global variables) on the IDA main thread.

    Returns:
        list[dict]: Each entry is:
            {"name": str, "ea": int, "kind": "function" | "global"}

    Notes:
    - Iterates idautils.Names() on the main thread for IDA 9.x safety.
    - A symbol is considered a "function" only if its EA is the function start EA.
      Any named item not at a function start is considered a "global".
    """
    symbols = []

    def _do():
        nonlocal symbols
        try:
            import idautils  # type: ignore
            import ida_funcs as _ida_funcs  # type: ignore
            import ida_name as _ida_name  # type: ignore
        except Exception:
            # Not running under IDA or imports failed; return empty
            symbols = []
            return 1

        try:
            seen = set()
            for ea, name in idautils.Names():
                try:
                    iea = int(ea)
                except Exception:
                    continue

                # De-duplicate by EA; keep first occurrence
                if iea in seen:
                    continue
                seen.add(iea)

                func = _ida_funcs.get_func(iea) if _ida_funcs else None
                is_func_start = bool(func and getattr(func, "start_ea", None) == iea)
                kind = "function" if is_func_start else "global"

                sym_name = name or (_ida_name.get_ea_name(iea) if _ida_name else "") or ""
                symbols.append({"name": sym_name, "ea": iea, "kind": kind})
        except Exception:
            # Best-effort enumeration; swallow to keep tool robust
            pass
        return 1

    run_on_main_thread(_do, write=False)
    return symbols
