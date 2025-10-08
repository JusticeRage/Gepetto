import pytest


@pytest.mark.usefixtures("_ensure_google_genai")
def test_tool_messages_batch_into_single_function_response():
    pytest.importorskip("google.genai.types")
    from gepetto.models import gemini

    query = [
        {"role": "user", "content": "hello"},
        {
            "role": "tool",
            "tool_call_id": "tool_call_0",
            "name": "decompile_function",
            "content": '{"type": "result", "data": {"ok": true}}',
        },
        {
            "role": "tool",
            "tool_call_id": "tool_call_1",
            "name": "rename_lvar",
            "content": '{"type": "result", "data": {"old_name": "Buf1"}}',
        },
        {"role": "assistant", "content": "done"},
    ]

    system_instruction, contents = gemini._convert_messages(query)

    assert system_instruction is None
    assert len(contents) == 3

    tool_content = contents[1]
    assert tool_content.role == "tool"
    assert len(tool_content.parts) == 2

    expected = [
        ("tool_call_0", "decompile_function"),
        ("tool_call_1", "rename_lvar"),
    ]
    observed = []
    for part, (call_id, name) in zip(tool_content.parts, expected):
        fr = getattr(part, "function_response", None)
        assert fr is not None
        observed.append((getattr(fr, "call_id", None), fr.name))

    assert observed == expected


@pytest.fixture
def _ensure_google_genai():
    pytest.importorskip("google.genai")
