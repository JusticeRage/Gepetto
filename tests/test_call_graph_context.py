import pytest
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
        lambda ea, _max_chars: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK),
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
        "status": "ok",
    }
    assert result["neighbours"] == [
        {
            "ea": "0x200",
            "name": "function_200",
            "relations": ["callee"],
            "status": "ok",
            "depth": 1,
            "code": "body_200",
            "truncated": False,
        },
        {
            "ea": "0x300",
            "name": "function_300",
            "relations": ["callee"],
            "status": "ok",
            "depth": 1,
            "code": "body_300",
            "truncated": False,
        },
        {
            "ea": "0x400",
            "name": "function_400",
            "relations": ["callee"],
            "status": "ok",
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
    monkeypatch.setattr(call_graph, "_decompiled_body", lambda ea, _max_chars: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK))

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

    code, truncated, status = call_graph._decompiled_body(0x100, 25)

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
        lambda _ea, budget: call_graph.Body(seen_budgets.append(budget) or f"body_budget_{budget}", False, call_graph.BodyStatus.OK),
    )

    result = call_graph.collect_call_graph_context(0x100, max_chars_per_function=7)

    assert result["root"]["code"] == "body_budget_7"
    assert seen_budgets == [7]


def test_collect_call_graph_context_allows_a_zero_depth_budget(monkeypatch):
    monkeypatch.setattr(call_graph, "resolve_func", lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name", lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours", lambda *_args: [0x200])
    monkeypatch.setattr(call_graph, "_decompiled_body", lambda ea, _budget: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK))

    result = call_graph.collect_call_graph_context(
        0x100,
        direction="callees",
        max_depth=0,
        max_functions=1,
    )

    assert result["neighbours"] == []
    assert result["limits"]["max_depth"] == 0


def _fake_graph(monkeypatch, graph, bodies=None):
    """A call graph with no IDA behind it.

    ``graph`` maps ``(ea, direction)`` to neighbours, so a test can make two
    functions call each other and have the traversal see it from both sides.
    """
    monkeypatch.setattr(call_graph, "resolve_func",
                        lambda ea: SimpleNamespace(start_ea=ea))
    monkeypatch.setattr(call_graph, "get_func_name",
                        lambda function: f"function_{function.start_ea:X}")
    monkeypatch.setattr(call_graph, "_function_neighbours",
                        lambda ea, direction: graph.get((ea, direction), []))
    if bodies is None:
        monkeypatch.setattr(call_graph, "_decompiled_body",
                            lambda ea, _budget: call_graph.Body(f"body_{ea:X}", False, call_graph.BodyStatus.OK))


# --- every returned body is bounded, diagnostics included --------------------

def test_a_decompilation_failure_is_bounded_like_any_other_body(monkeypatch):
    """A failure message is text the caller did not ask for and cannot size."""
    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: (_ for _ in ()).throw(RuntimeError("boom " * 200)))

    code, truncated, status = call_graph._decompiled_body(0x100, 40)

    assert len(code) == 40
    assert truncated is True
    assert status == "failed"


def test_an_empty_decompilation_is_bounded_too(monkeypatch):
    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "   \n  ")

    code, truncated, status = call_graph._decompiled_body(0x100, 12)

    assert len(code) == 12
    assert truncated is True
    assert status == "empty"


def test_the_smallest_budget_still_holds_on_every_path(monkeypatch):
    """max_chars_per_function=1 is the case that made the bug obvious."""
    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "int f(void) { return 1; }")
    assert len(call_graph._decompiled_body(0x100, 1)[0]) == 1

    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "")
    assert len(call_graph._decompiled_body(0x100, 1)[0]) == 1

    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: (_ for _ in ()).throw(RuntimeError("nope")))
    assert len(call_graph._decompiled_body(0x100, 1)[0]) == 1


def test_status_survives_a_bound_that_destroys_the_message(monkeypatch):
    """Truncated to a character, `/` is indistinguishable from code."""
    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: (_ for _ in ()).throw(RuntimeError("nope")))

    _code, _truncated, status = call_graph._decompiled_body(0x100, 1)

    assert status == "failed"


def test_a_body_that_fits_is_not_marked_truncated(monkeypatch):
    monkeypatch.setattr(call_graph, "decompile_function", lambda ea: "int f;")

    code, truncated, status = call_graph._decompiled_body(0x100, 80)

    assert (code, truncated, status) == ("int f;", False, "ok")


# --- direction="both" must not lose a relation -------------------------------

def test_mutual_recursion_is_reported_from_both_sides(monkeypatch):
    """A single visited set records B under whichever direction reached it
    first and drops the other, so `both` returned less than callers plus
    callees."""
    _fake_graph(monkeypatch, {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): [0x200],
        (0x200, "callers"): [0x100],
        (0x200, "callees"): [0x100],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8)

    assert len(result["neighbours"]) == 1, "one function, not two entries"
    assert result["neighbours"][0]["relations"] == ["callee", "caller"]


def test_both_returns_the_union_of_the_single_directions(monkeypatch):
    graph = {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): [0x300],
    }
    _fake_graph(monkeypatch, graph)

    def names(direction):
        found = call_graph.collect_call_graph_context(
            0x100, direction=direction, max_depth=1, max_functions=8)
        return {n["ea"] for n in found["neighbours"]}

    assert names("both") == names("callers") | names("callees")


def test_a_one_sided_neighbour_keeps_its_single_relation(monkeypatch):
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200]})

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8)

    assert result["neighbours"][0]["relations"] == ["callee"]


def test_a_neighbour_reached_twice_is_decompiled_once(monkeypatch):
    """Aggregating is not only tidier output; it halves the work."""
    decompiled = []
    _fake_graph(monkeypatch, {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): [0x200],
    }, bodies=True)
    monkeypatch.setattr(
        call_graph, "_decompiled_body",
        lambda ea, _budget: call_graph.Body(decompiled.append(ea) or f"body_{ea:X}", False, call_graph.BodyStatus.OK))

    call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=1, max_functions=8)

    assert decompiled.count(0x200) == 1, "reached as caller and as callee"
    assert decompiled == [0x100, 0x200], "the root, then the neighbour, once"


def test_the_nearer_depth_wins_when_a_neighbour_is_reached_twice(monkeypatch):
    _fake_graph(monkeypatch, {
        (0x100, "callees"): [0x200],
        (0x200, "callees"): [0x300],
        (0x100, "callers"): [0x300],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=2, max_functions=8)

    reached = {n["ea"]: n for n in result["neighbours"]}
    assert reached["0x300"]["depth"] == 1, "a caller at depth 1 beats a callee at 2"
    assert reached["0x300"]["relations"] == ["callee", "caller"]


# --- budget_exhausted means truncated, not merely full -----------------------

def test_a_budget_that_fills_exactly_is_not_a_truncation(monkeypatch):
    """The old flag was `returned == max_functions`, true even when the graph
    had nothing else to give."""
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200, 0x300]})

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=2, max_functions=2)

    assert result["limits"]["returned"] == 2
    assert result["limits"]["budget_exhausted"] is False


def test_evidence_left_out_is_reported_as_truncation(monkeypatch):
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200, 0x300, 0x400]})

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=2, max_functions=2)

    assert result["limits"]["returned"] == 2
    assert result["limits"]["budget_exhausted"] is True


def test_a_neighbour_cut_off_a_level_down_still_counts(monkeypatch):
    """The budget can fill exactly as a depth finishes, leaving whole nodes
    unexplored. Nothing was refused on the way, so it takes a look to tell."""
    _fake_graph(monkeypatch, {
        (0x100, "callees"): [0x200, 0x300],
        (0x300, "callees"): [0x400],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=2, max_functions=2)

    assert result["limits"]["returned"] == 2
    assert result["limits"]["budget_exhausted"] is True


def test_an_already_seen_neighbour_is_not_counted_as_lost(monkeypatch):
    """Re-reaching a function already returned is not evidence left out."""
    _fake_graph(monkeypatch, {
        (0x100, "callees"): [0x200, 0x300],
        (0x200, "callees"): [0x300],
        (0x300, "callees"): [0x200],
    })

    result = call_graph.collect_call_graph_context(
        0x100, direction="callees", max_depth=3, max_functions=2)

    assert result["limits"]["budget_exhausted"] is False


# --- the enums, and why they are string enums --------------------------------

def test_a_status_renders_as_the_plain_string_everywhere():
    """The reason StrEnum is backported rather than using (str, Enum).

    A bare mixin serialises correctly but renders as `BodyStatus.OK` from
    str() and f-strings, so the first log line or prompt that interpolates one
    prints the wrong thing -- and nothing fails while it does.
    """
    status = call_graph.BodyStatus.OK

    assert str(status) == "ok"
    assert f"{status}" == "ok"
    assert "{}".format(status) == "ok"
    assert status == "ok", "still compares equal to the string it replaces"


def test_a_status_survives_the_json_the_tool_sends():
    """json.dumps refuses a bare Enum, and would refuse it in the tool path
    only -- long after the collector's own tests had passed."""
    import json

    assert json.dumps({"status": call_graph.BodyStatus.FAILED}) == '{"status": "failed"}'


def test_a_relation_is_a_string_enum_too():
    assert str(call_graph.Relation.CALLER) == "caller"
    assert call_graph.Relation.for_direction("callers") is call_graph.Relation.CALLER
    assert call_graph.Relation.for_direction("callees") is call_graph.Relation.CALLEE


def test_relations_serialise_as_a_plain_list_of_strings():
    import json

    relations = [call_graph.Relation.CALLEE, call_graph.Relation.CALLER]

    assert json.dumps(relations) == '["callee", "caller"]'


# --- the neighbour keeps its own invariants ----------------------------------

def test_a_neighbour_reached_again_keeps_its_relations_unique_and_ordered():
    body = call_graph.Body("code", False, call_graph.BodyStatus.OK)
    neighbour = call_graph.Neighbour(
        ea=0x200, name="f", depth=2, body=body,
        relations=[call_graph.Relation.CALLER])

    neighbour.also_reached_as(call_graph.Relation.CALLEE, 1)
    neighbour.also_reached_as(call_graph.Relation.CALLEE, 3)

    assert neighbour.relations == ["callee", "caller"], "unique and ordered"
    assert neighbour.depth == 1, "the nearer depth wins, and later ones do not undo it"


def test_a_neighbour_renders_the_payload_the_tool_sends():
    body = call_graph.Body("int f;", True, call_graph.BodyStatus.OK)
    neighbour = call_graph.Neighbour(
        ea=0x200, name="f", depth=1, body=body,
        relations=[call_graph.Relation.CALLEE])

    assert neighbour.as_payload() == {
        "ea": "0x200",
        "name": "f",
        "relations": ["callee"],
        "depth": 1,
        "code": "int f;",
        "truncated": True,
        "status": "ok",
    }


def test_a_direction_is_named_rather_than_spelled_out():
    assert call_graph.Direction.parse("both") is call_graph.Direction.BOTH
    assert call_graph.Direction.BOTH == "both", "still the string it serialises as"


def test_an_unknown_direction_is_refused_with_the_same_message():
    import pytest

    with pytest.raises(ValueError, match="must be callers, callees or both"):
        call_graph.Direction.parse("sideways")


def test_a_relation_is_never_guessed_from_an_unknown_direction():
    """The conditional this replaced had an else, so a typo, an empty string
    and None all came back CALLEE -- a confident wrong answer."""
    import pytest

    for bad in ("sideways", "", None, "caller"):
        with pytest.raises(ValueError):
            call_graph.Relation.for_direction(bad)


def test_both_names_two_relations_so_asking_for_one_is_an_error():
    import pytest

    with pytest.raises(ValueError, match="two relations"):
        call_graph.Relation.for_direction(call_graph.Direction.BOTH)


def test_the_three_xref_parameters_agree_with_each_other():
    """They were three separate conditionals; getting one wrong queried the
    other direction and nothing said so."""
    callers = call_graph.Direction.CALLERS.xrefs
    callees = call_graph.Direction.CALLEES.xrefs

    assert callers == ("to", "from_func", "from_ea")
    assert callees == ("from", "to_func", "to_ea")
    assert set(callers) & set(callees) == set(), "no parameter shared by both"


def test_both_has_no_single_xref_query():
    import pytest

    with pytest.raises(ValueError, match="walks two ways"):
        call_graph.Direction.BOTH.xrefs


def test_neighbours_asks_for_the_direction_it_was_given(monkeypatch):
    """The parameters reaching the xref API are the direction's, not a guess."""
    asked = {}

    def fake_xrefs(**kwargs):
        asked.update(kwargs)
        return {"xrefs": []}

    monkeypatch.setattr(call_graph, "get_xrefs_unified", fake_xrefs)

    call_graph._function_neighbours(0x100, call_graph.Direction.CALLERS)
    assert (asked["direction"], asked["collapse_by"]) == ("to", "from_func")

    call_graph._function_neighbours(0x100, call_graph.Direction.CALLEES)
    assert (asked["direction"], asked["collapse_by"]) == ("from", "to_func")


def test_neighbours_refuses_a_direction_that_is_not_one(monkeypatch):
    import pytest

    monkeypatch.setattr(call_graph, "get_xrefs_unified",
                        lambda **kwargs: {"xrefs": []})

    with pytest.raises(ValueError):
        call_graph._function_neighbours(0x100, "sideways")
    with pytest.raises(ValueError, match="walks two ways"):
        call_graph._function_neighbours(0x100, call_graph.Direction.BOTH)


@pytest.mark.parametrize("extra", [False, True])
def test_full_budget_preserves_mutual_relation(monkeypatch, extra):
    graph = {
        (0x100, "callers"): [0x200],
        (0x100, "callees"): ([0x300] if extra else []) + [0x200],
    }
    _fake_graph(monkeypatch, graph, bodies=True)
    decompiled = []
    monkeypatch.setattr(call_graph, "decompile_function",
                        lambda ea: decompiled.append(ea) or "body")
    result = call_graph.collect_call_graph_context(
        0x100, direction="both", max_depth=2, max_functions=1)
    assert len(result["neighbours"]) == 1
    assert result["neighbours"][0]["relations"] == ["callee", "caller"]
    assert result["limits"]["budget_exhausted"] is extra
    assert decompiled == [0x100, 0x200]


def test_function_name_resolves_to_root(monkeypatch):
    _fake_graph(monkeypatch, {})
    def resolve(ea=None, name=None):
        if name == "btel::TimeSource::clock":
            return SimpleNamespace(start_ea=0x100)
        raise ValueError("Name not found")
    monkeypatch.setattr(call_graph, "resolve_func", resolve)
    result = call_graph.collect_call_graph_context("btel::TimeSource::clock", max_depth=0)
    assert result["root"]["ea"] == "0x100"
    with pytest.raises(ValueError, match="Name not found"):
        call_graph.collect_call_graph_context("missing_function")


def test_named_root_matches_address_forms_in_ida(create_idb, monkeypatch):
    named = call_graph.collect_call_graph_context("main", max_depth=0)
    address = int(named["root"]["ea"], 16)
    monkeypatch.setattr(call_graph, "safe_get_screen_ea", lambda: address)
    for value in (address, hex(address), str(address), f"{address:X}h", None):
        assert call_graph.collect_call_graph_context(value, max_depth=0) == named


def test_full_budget_finishes_relations_at_deeper_depth(monkeypatch):
    _fake_graph(monkeypatch, {
        (0x100, "callers"): [0x200, 0x300],
        (0x100, "callees"): [0x300],
        (0x300, "callees"): [0x200],
    })
    result = call_graph.collect_call_graph_context(
        0x100, max_depth=2, max_functions=2)
    assert [n["relations"] for n in result["neighbours"]] == [
        ["callee", "caller"], ["callee", "caller"]]
    assert result["limits"]["budget_exhausted"] is False


def test_zero_function_budget_reports_omitted_neighbours(monkeypatch):
    _fake_graph(monkeypatch, {(0x100, "callees"): [0x200]})
    result = call_graph.collect_call_graph_context(0x100, max_functions=0)
    assert result["neighbours"] == []
    assert result["limits"]["budget_exhausted"] is True
