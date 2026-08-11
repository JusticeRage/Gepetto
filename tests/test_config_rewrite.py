"""Direct tests for the in-place INI rewriter.

The rewriter is what stops update_config deleting the user's comments, but it
edits text rather than reserialising, so its edge cases are the file shapes a
real config actually contains -- above all an option that is present but empty,
which is how every API key ships.
"""

import configparser
import textwrap

import pytest

from gepetto.config import _set_option_in_text


def parse(text):
    parser = configparser.RawConfigParser()
    parser.read_string(text)
    return parser


SAMPLE = textwrap.dedent(
    """\
    # Leading comment.

    [Gepetto]
    # Which model to use.
    MODEL = gpt-4o
    LANGUAGE =

    [OpenAI]
    # Set your API key here.
    API_KEY =
    BASE_URL =
    """
)


def test_setting_an_empty_option_keeps_it_on_its_own_line():
    # The regression: a greedy \\s* consumed the newline, producing
    # "API_KEY =\\nsk-secret" and a file that no longer parses.
    result = _set_option_in_text(SAMPLE, "OpenAI", "API_KEY", "sk-secret")

    assert "API_KEY = sk-secret" in result
    assert parse(result).get("OpenAI", "API_KEY") == "sk-secret"


def test_the_file_still_parses_after_filling_every_empty_option():
    result = SAMPLE
    for section, option, value in [
        ("OpenAI", "API_KEY", "sk-secret"),
        ("OpenAI", "BASE_URL", "https://example.test/v1"),
        ("Gepetto", "LANGUAGE", "fr_FR"),
    ]:
        result = _set_option_in_text(result, section, option, value)

    parsed = parse(result)
    assert parsed.get("OpenAI", "API_KEY") == "sk-secret"
    assert parsed.get("OpenAI", "BASE_URL") == "https://example.test/v1"
    assert parsed.get("Gepetto", "LANGUAGE") == "fr_FR"
    assert parsed.get("Gepetto", "MODEL") == "gpt-4o"
    assert "# Set your API key here." in result


def test_line_count_is_unchanged_when_replacing_a_value():
    before = SAMPLE.count("\n")
    result = _set_option_in_text(SAMPLE, "OpenAI", "API_KEY", "sk-secret")
    assert result.count("\n") == before


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("KEY=", "KEY=v"),          # compact style preserved
        ("KEY =", "KEY = v"),
        ("KEY  =  ", "KEY  =  v"),
        ("KEY:", "KEY:v"),
        ("KEY : ", "KEY : v"),
        ("  KEY = ", "  KEY = v"),
    ],
)
def test_separator_and_spacing_are_preserved(line, expected):
    text = f"[S]\n{line}\n"
    result = _set_option_in_text(text, "S", "KEY", "v")
    assert result == f"[S]\n{expected}\n"


def test_a_value_is_replaced_not_appended_to():
    text = "[S]\nKEY = old\n"
    assert _set_option_in_text(text, "S", "KEY", "new") == "[S]\nKEY = new\n"


def test_only_the_named_option_is_touched():
    text = "[S]\nKEY =\nKEY_EXTRA = keep\n"
    result = _set_option_in_text(text, "S", "KEY", "v")
    assert result == "[S]\nKEY = v\nKEY_EXTRA = keep\n"


def test_an_option_in_another_section_is_not_matched():
    text = "[A]\nKEY =\n\n[B]\nKEY =\n"
    result = _set_option_in_text(text, "B", "KEY", "v")
    parsed = parse(result)
    assert parsed.get("B", "KEY") == "v"
    assert parsed.get("A", "KEY") == ""


def test_comment_lines_are_never_mistaken_for_options():
    text = "[S]\n# KEY = do not touch this\nKEY =\n"
    result = _set_option_in_text(text, "S", "KEY", "v")
    assert "# KEY = do not touch this" in result
    assert parse(result).get("S", "KEY") == "v"


def test_a_multi_line_value_is_replaced_whole():
    text = "[S]\nKEY = first\n    continued\nOTHER = keep\n"
    result = _set_option_in_text(text, "S", "KEY", "v")
    parsed = parse(result)
    assert parsed.get("S", "KEY") == "v"
    assert parsed.get("S", "OTHER") == "keep"
