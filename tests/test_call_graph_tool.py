import json
from types import SimpleNamespace

from gepetto.ida import cli
from gepetto.ida.tools import get_call_graph_context
from gepetto.ida.tools.tools import TOOLS


def _schema(name):
    return next(tool["function"] for tool in TOOLS if tool["function"]["name"] == name)


def test_call_graph_context_is_exposed_as_a_bounded_model_tool():
    schema = _schema("get_call_graph_context")
    properties = schema["parameters"]["properties"]

    assert properties["ea"]["anyOf"] == [{"type": "integer"}, {"type": "string"}]
    assert properties["direction"]["enum"] == ["callers", "callees", "both"]
    assert properties["max_depth"]["minimum"] == 0
    assert properties["max_functions"]["minimum"] == 0
    assert properties["max_chars_per_function"]["minimum"] == 1
    assert "get_call_graph_context" in cli.MESSAGES[0]["content"]


def test_call_graph_context_handler_passes_model_bounds_to_the_collector(monkeypatch):
    received = {}
    expected = {"root": {"ea": "0x100"}, "neighbours": [], "limits": {}}
    monkeypatch.setattr(
        get_call_graph_context,
        "collect_call_graph_context",
        lambda **kwargs: received.update(kwargs) or expected,
    )
    tc = SimpleNamespace(
        id="call-1",
        function=SimpleNamespace(
            name="get_call_graph_context",
            arguments=json.dumps(
                {
                    "ea": 256,
                    "direction": "callees",
                    "max_depth": 1,
                    "max_functions": 3,
                    "max_chars_per_function": 600,
                }
            ),
        ),
    )
    messages = []

    get_call_graph_context.handle_get_call_graph_context_tc(tc, messages)

    assert received == {
        "ea": 256,
        "direction": "callees",
        "max_depth": 1,
        "max_functions": 3,
        "max_chars_per_function": 600,
    }
    assert json.loads(messages[-1]["content"]) == {"type": "result", "data": expected}


def test_call_graph_context_handler_keeps_collector_defaults_when_bounds_are_omitted(monkeypatch):
    received = {}
    monkeypatch.setattr(
        get_call_graph_context,
        "collect_call_graph_context",
        lambda **kwargs: received.update(kwargs) or {},
    )
    tc = SimpleNamespace(
        id="call-2",
        function=SimpleNamespace(name="get_call_graph_context", arguments="{}"),
    )

    get_call_graph_context.handle_get_call_graph_context_tc(tc, [])

    assert received == {"ea": None, "direction": "both"}


def test_cli_dispatches_the_call_graph_tool(monkeypatch):
    invoked = []
    tc = SimpleNamespace(
        function=SimpleNamespace(name="get_call_graph_context", arguments="{}")
    )
    monkeypatch.setattr(
        cli.ida_tools.get_call_graph_context,
        "handle_get_call_graph_context_tc",
        lambda tool_call, messages: invoked.append((tool_call, messages)),
    )
    messages = []

    cli.dispatch_tool_call(tc, messages)
    assert invoked == [(tc, messages)]


def test_cli_dispatcher_returns_an_error_for_an_unknown_tool():
    tc = SimpleNamespace(
        id="unknown-call",
        function=SimpleNamespace(name="not_a_gepetto_tool", arguments="{}"),
    )
    messages = []

    cli.dispatch_tool_call(tc, messages)

    assert json.loads(messages[-1]["content"]) == {
        "type": "error",
        "error": {
            "message": "Unknown tool: not_a_gepetto_tool",
            "context": {"tool_name": "not_a_gepetto_tool"},
        },
    }


# --- the schema and the code have to agree on the vocabulary -----------------

def test_the_schema_offers_exactly_the_directions_the_code_accepts():
    """The schema is what the model is told; Direction is what the collector
    takes. Nothing links them at runtime, so they can drift apart silently --
    the model gets offered a value that raises, or is never told about one that
    works. Neither shows up until someone reads a confusing tool error.
    """
    from gepetto.ida.call_graph import Direction

    declared = _schema("get_call_graph_context")["parameters"]["properties"]["direction"]

    assert declared["enum"] == [direction.value for direction in Direction]
    assert declared["default"] == Direction.BOTH


def test_every_direction_the_schema_offers_is_one_the_collector_parses():
    """Equality of two lists is weaker than it looks; this checks the values
    actually work rather than merely matching a list built the same way."""
    from gepetto.ida.call_graph import Direction

    declared = _schema("get_call_graph_context")["parameters"]["properties"]["direction"]

    for value in declared["enum"]:
        assert Direction.parse(value).value == value


def test_the_adapter_defaults_to_the_direction_the_schema_advertises():
    import inspect

    from gepetto.ida.call_graph import Direction

    declared = _schema("get_call_graph_context")["parameters"]["properties"]["direction"]
    signature = inspect.signature(get_call_graph_context.get_call_graph_context)

    assert signature.parameters["direction"].default == declared["default"]
    assert signature.parameters["direction"].default is Direction.BOTH
