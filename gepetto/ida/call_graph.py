"""Bounded call-graph context for a function and its decompiled neighbours.

This is a domain API, not a model-tool handler.  A user tool can expose it to
the model, while a context provider can call it directly without depending on
tool registration, JSON tool-call objects, or handler globals::

    from gepetto.ida.call_graph import collect_call_graph_context

    context = collect_call_graph_context(ea, direction="callees")

``max_chars_per_function`` is an exact Unicode-code-point limit for every
decompiled body, including the truncation marker.  Model-token budgeting is a
caller policy because it depends on the selected model and prompt shape.
"""

from __future__ import annotations

from typing import Any

from gepetto.ida.tools.decompile_function import decompile_function
from gepetto.ida.tools.get_xrefs import get_xrefs_unified
from gepetto.ida.utils.function_helpers import get_func_name, parse_ea, resolve_func
from gepetto.ida.utils.thread_helpers import safe_get_screen_ea


DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_FUNCTIONS = 8
DEFAULT_MAX_CHARS_PER_FUNCTION = 1200
_TRUNCATION_SUFFIX = "\n// ... truncated ..."


def _function_neighbours(func_ea: int, direction: str) -> list[int]:
    """Return unique function starts reached by call xrefs in ``direction``."""
    xrefs = get_xrefs_unified(
        scope="function",
        subject=hex(func_ea),
        direction="to" if direction == "callers" else "from",
        kind="code",
        only_calls=True,
        collapse_by="from_func" if direction == "callers" else "to_func",
        enrich_names=False,
    )

    endpoint = "from_ea" if direction == "callers" else "to_ea"
    neighbours: list[int] = []
    for xref in xrefs["xrefs"]:
        try:
            function = resolve_func(ea=int(xref[endpoint]))
        except ValueError:
            continue
        if function.start_ea not in neighbours:
            neighbours.append(function.start_ea)
    return neighbours


def _decompiled_body(func_ea: int, max_chars: int) -> tuple[str, bool]:
    try:
        code = str(decompile_function(ea=func_ea))
    except Exception as exc:
        return f"// decompilation failed: {exc}", False
    if not code.strip():
        return "// decompilation produced no output", False
    if len(code) > max_chars:
        prefix_length = max_chars - len(_TRUNCATION_SUFFIX)
        if prefix_length <= 0:
            return code[:max_chars], True
        return code[:prefix_length] + _TRUNCATION_SUFFIX, True
    return code, False


def _limit(value: int, name: str, minimum: int) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if limit < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return limit


def _walk(
    root_ea: int,
    direction: str,
    max_depth: int,
    max_functions: int,
    max_chars_per_function: int,
) -> list[dict[str, Any]]:
    """Breadth-first neighbourhood of ``root_ea``, excluding the root."""
    directions = ["callers", "callees"] if direction == "both" else [direction]
    visited = {root_ea}
    collected: list[dict[str, Any]] = []
    frontier = [(root_ea, 0, current_direction) for current_direction in directions]

    while frontier and len(collected) < max_functions:
        next_frontier = []
        for ea, depth, current_direction in frontier:
            if depth >= max_depth or len(collected) >= max_functions:
                continue
            for neighbour in _function_neighbours(ea, current_direction):
                if len(collected) >= max_functions:
                    break
                if neighbour in visited:
                    continue
                visited.add(neighbour)
                function = resolve_func(ea=neighbour)
                code, truncated = _decompiled_body(neighbour, max_chars_per_function)
                collected.append(
                    {
                        "ea": hex(neighbour),
                        "name": get_func_name(function) or f"sub_{neighbour:X}",
                        "relation": "caller" if current_direction == "callers" else "callee",
                        "depth": depth + 1,
                        "code": code,
                        "truncated": truncated,
                    }
                )
                next_frontier.append((neighbour, depth + 1, current_direction))
        frontier = next_frontier
    return collected


def collect_call_graph_context(
    ea: int | str | None = None,
    *,
    direction: str = "both",
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_chars_per_function: int = DEFAULT_MAX_CHARS_PER_FUNCTION,
) -> dict[str, Any]:
    """Return a bounded breadth-first call-graph slice around a function.

    The returned root and each neighbour include a decompiled body.  This is a
    library API: callers own policy such as configuration and prompt budgets.
    """
    if direction not in {"callers", "callees", "both"}:
        raise ValueError(f"direction must be callers, callees or both (got {direction!r})")

    max_depth = _limit(max_depth, "max_depth", 0)
    max_functions = _limit(max_functions, "max_functions", 0)
    max_chars_per_function = _limit(max_chars_per_function, "max_chars_per_function", 1)

    root_ea = parse_ea(ea) if ea is not None else safe_get_screen_ea()
    root_function = resolve_func(ea=root_ea)
    root_ea = root_function.start_ea
    root_code, root_truncated = _decompiled_body(root_ea, max_chars_per_function)
    neighbours = _walk(
        root_ea,
        direction,
        max_depth,
        max_functions,
        max_chars_per_function,
    )

    return {
        "root": {
            "ea": hex(root_ea),
            "name": get_func_name(root_function) or f"sub_{root_ea:X}",
            "code": root_code,
            "truncated": root_truncated,
        },
        "neighbours": neighbours,
        "limits": {
            "direction": direction,
            "max_depth": max_depth,
            "max_functions": max_functions,
            "returned": len(neighbours),
            "budget_exhausted": len(neighbours) >= max_functions,
        },
    }


__all__ = ["collect_call_graph_context"]
