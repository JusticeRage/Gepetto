from gepetto.ida import cli
from gepetto.ida.tools.tools import TOOLS


def _schema(name):
    return next(tool["function"] for tool in TOOLS if tool["function"]["name"] == name)


def test_decompile_accepts_the_integer_ea_returned_by_current_function():
    ea = _schema("decompile_function")["parameters"]["properties"]["ea"]

    assert ea["anyOf"] == [{"type": "integer"}, {"type": "string"}]


def test_prompt_preserves_tool_returned_addresses_for_tool_arguments():
    prompt = cli.MESSAGES[0]["content"]

    assert "Values returned by a tool must be passed unchanged to later tools." in prompt
    assert "never convert decimal numbers to hexadecimal yourself" not in prompt
