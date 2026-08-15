from types import SimpleNamespace

from gepetto.ida import call_graph


def test_collect_call_graph_context_uses_breadth_first_order_within_the_budget(monkeypatch):
    graph = {
        0x100: [0x200, 0x300],
        0x200: [0x400],
        0x300: [0x500],
    }

    monkeypatch.setattr(
        call_graph,
        "resolve_func",
        lambda ea: SimpleNamespace(start_ea=ea),
    )
    monkeypatch.setattr(
        call_graph,
        "get_func_name",
        lambda function: f"function_{function.start_ea:X}",
    )
    monkeypatch.setattr(
        call_graph,
        "_function_neighbours",
        lambda ea, _direction: graph.get(ea, []),
    )
    monkeypatch.setattr(
        call_graph,
        "_decompiled_body",
        lambda ea, _max_chars: (f"body_{ea:X}", False),
    )

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=2,
        max_functions=3,
        max_chars_per_function=80,
    )

    assert result["root"] == {
        "ea": "0x100",
        "name": "function_100",
        "code": "body_100",
        "truncated": False,
    }
    assert result["neighbours"] == [
        {
            "ea": "0x200",
            "name": "function_200",
            "relation": "callee",
            "depth": 1,
            "code": "body_200",
            "truncated": False,
        },
        {
            "ea": "0x300",
            "name": "function_300",
            "relation": "callee",
            "depth": 1,
            "code": "body_300",
            "truncated": False,
        },
        {
            "ea": "0x400",
            "name": "function_400",
            "relation": "callee",
            "depth": 2,
            "code": "body_400",
            "truncated": False,
        },
    ]
    assert result["limits"] == {
        "direction": "callees",
        "max_depth": 2,
        "max_functions": 3,
        "returned": 3,
        "budget_exhausted": True,
    }


def test_collect_call_graph_context_skips_call_targets_outside_a_function(monkeypatch):
    def resolve_function(ea):
        if ea == 0xDEAD:
            raise ValueError("EA 0xDEAD is not inside a function")
        return SimpleNamespace(start_ea=ea)

    monkeypatch.setattr(call_graph, "resolve_func", resolve_function)
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(
        call_graph,
        "get_xrefs_unified",
        lambda **kwargs: {
            "xrefs": [
                {"to_ea": 0xDEAD},
                {"to_ea": 0x200},
            ] if kwargs["subject"] == "0x100" else [],
        },
    )
    monkeypatch.setattr(call_graph, "_decompiled_body", lambda ea, _max_chars: (f"body_{ea:X}", False))

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=1,
        max_functions=2,
    )

    assert [neighbour["ea"] for neighbour in result["neighbours"]] == ["0x200"]


def test_decompiled_body_honors_an_exact_unicode_code_point_budget(monkeypatch):
    monkeypatch.setattr(
        call_graph,
        "decompile_function",
        lambda **_kwargs: "\u03b1\u03b2\u03b3\u03b4\u03b5\u03b6\u03b7\u03b8\u03b9\u03ba\u03bb\u03bc\u03bd\u03be\u03bf\u03c0\u03c1\u03c3\u03c4\u03c5\u03c6\u03c7\u03c8\u03c9\u03b1\u03b2\u03b3\u03b4\u03b5\u03b6",
    )

    code, truncated = call_graph._decompiled_body(0x100, 25)

    assert code == "\u03b1\u03b2\u03b3\u03b4\n// ... truncated ..."
    assert len(code) == 25
    assert code.encode("utf-8").decode("utf-8") == code
    assert truncated is True


def test_collect_call_graph_context_honors_an_explicit_body_budget(monkeypatch):
    seen_budgets = []

    monkeypatch.setattr(call_graph, "resolve_func", lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours", lambda *_args: [])
    monkeypatch.setattr(
        call_graph,
        "_decompiled_body",
        lambda _ea, budget: (seen_budgets.append(budget) or f"body_budget_{budget}", False),
    )

    result = call_graph.collect_call_graph_context(0x100, max_chars_per_function=7)

    assert result["root"]["code"] == "body_budget_7"
    assert seen_budgets == [7]


def test_collect_call_graph_context_allows_a_zero_depth_budget(monkeypatch):
    monkeypatch.setattr(call_graph, "resolve_func", lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours", lambda *_args: [0x200])
    monkeypatch.setattr(call_graph, "_decompiled_body", lambda ea, _budget: (f"body_{ea:X}", False))

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=0,
        max_functions=1,
    )

    assert result["neighbours"] == []
    assert result["limits"]["max_depth"] == 0
