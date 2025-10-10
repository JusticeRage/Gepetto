import pytest

from gepetto.ida.utils import function_helpers
from gepetto.ida.tools.rename_function import rename_function
from gepetto.ida.tools.get_disasm import get_disasm
from gepetto.ida.tools.get_bytes import get_bytes
from gepetto.ida.tools.decompile_function import decompile_function
from gepetto.ida.tools.get_xrefs import get_xrefs_unified
from gepetto.ida.tools.search import search, list_strings

def test_resolve_name(create_idb):
    ea = function_helpers.resolve_ea("main")
    assert ea == 0x140017F60

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("target_name", "start_ea", "end_ea"),
    [
        pytest.param("main",          0x140017F60, 0x140019417, id="main"),
        pytest.param("sub_140019700", 0x140019700, 0x1400198C2, id="sub_140019700"),
    ],
)
def test_resolve_function_by_name(create_idb, target_name, start_ea, end_ea):
    f = function_helpers.resolve_func(name=target_name)
    assert f.start_ea == start_ea
    assert f.end_ea == end_ea

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("target_ea", "start_ea", "end_ea", "expected_name"),
    [
        pytest.param(0x140017F70, 0x140017F60, 0x140019417, "main", id="main"),
        pytest.param(0x140019800, 0x140019700, 0x1400198C2, "sub_140019700", id="sub_140019700"),
    ],
)
def test_resolve_function_by_ea(create_idb, target_ea, start_ea, end_ea, expected_name):
    f = function_helpers.resolve_func(ea=target_ea)
    assert f.start_ea == start_ea
    assert f.end_ea == end_ea
    assert function_helpers.get_func_name(f) == expected_name

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("target_name", "expected_fragment"),
    [
        pytest.param("main",            "mov     [rsp-8+arg_10], rbx",  id="main"),
        pytest.param("sub_140019700",   "mov     [rsp+arg_0], rbx",     id="sub_140019700"),
    ],
)
def test_get_disasm(create_idb, target_name, expected_fragment):
    ea = function_helpers.resolve_ea(target_name)
    result = get_disasm(ea)

    assert result["ea"] == ea
    assert isinstance(result["disasm"], str)
    assert result["disasm"].strip() != ""
    assert expected_fragment == result["disasm"]

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("target_name", "size", "expected_prefix"),
    [
        pytest.param("main", 4, "0x48 0x89 0x5C 0x24", id="main-bytes"),
        pytest.param("xmmword_1400D69F0", 4, "0x00 0x00 0x00 0x00", id="constant-bytes")
    ],
)
def test_get_bytes(create_idb, target_name, size, expected_prefix):
    ea = function_helpers.resolve_ea(target_name)
    result = get_bytes(ea, size)

    assert result["ea"] == ea
    assert result["size"] == size

    byte_tokens = result["bytes"].split()
    assert len(byte_tokens) == size
    for token in byte_tokens:
        assert token.startswith("0x")

    assert result["bytes"].startswith(expected_prefix)

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("target_name", "expected_fragment"),
    [
        pytest.param("sub_1400D3720", "void __fastcall sub_1400D3720()\n{\n  unknown_libname_7(&unk_140118890);\n}\n", id="full"),
        pytest.param("main", "v34 = boost::program_options::abstract_variables_map::operator[](", id="main"),
    ],
)
def test_get_function_code(create_idb, target_name, expected_fragment):
    result = decompile_function(name=target_name)
    assert expected_fragment in str(result)

# ---------------------------------------------------------------------------

@pytest.fixture
def function_rename_guard():
    """Track function renames so they can be reverted after the test."""

    to_restore: list[tuple[int, str]] = []

    def _rename(target_name: str, new_name: str):
        func = function_helpers.resolve_func(name=target_name)
        original_name = function_helpers.get_func_name(func)
        ea = int(func.start_ea)
        to_restore.append((ea, original_name))
        result = rename_function(ea=ea, new_name=new_name)
        return result, original_name

    yield _rename

    while to_restore:
        ea, original_name = to_restore.pop()
        rename_function(ea=ea, new_name=original_name)


@pytest.mark.parametrize(
    ("target_name", "new_name", "expected_old_name"),
    [
        pytest.param("main", "main__gepetto_test", "main", id="main"),
    ],
)
def test_rename_function_round_trip(create_idb, function_rename_guard, target_name, new_name, expected_old_name):
    result, original_name = function_rename_guard(target_name, new_name)
    assert result["new_name"] == new_name
    assert result["ea"] == function_helpers.resolve_ea(new_name)
    assert result["old_name"] == original_name
    assert original_name == expected_old_name

# ---------------------------------------------------------------------------

import pytest
from typing import Any

@pytest.mark.parametrize(
    ("scope", "subject", "direction", "expected", "kwargs"),
    [
        pytest.param(
            "function",
            "0x140017F60",
            "to",
            [{
                "from_ea": 5369367579,
                "to_ea": 5368807264,
                "direction": "to",
                "kind": "code",
                "type": 17,
                "from_func": "?__scrt_common_main_seh@@YAHXZ",
                "to_func": "main",
            }],
            {"only_calls": True},
            id="function-to",
        ),
        pytest.param(
            "name",
            "unk_1400D6A20",
            "both",
            [
                {
                    "from_ea": 5368821643,
                    "to_ea": 5369588256,
                    "direction": "to",
                    "kind": "data",
                    "type": 1,
                    "from_func": "sub_14001B300",
                    "to_func": "unk_1400D6A20"
                }
            ],
            {},
            id="constant-both",
        )
    ]
)
def test_get_xrefs_unified(create_idb, scope: str, subject: str, direction: str,
                           expected: list[dict[str, Any]], kwargs: dict[str, Any]):
    # pass the arbitrary kwargs straight through
    result = get_xrefs_unified(scope=scope, subject=subject, direction=direction, **kwargs)

    assert result["scope"] == scope
    assert result["direction"] == direction
    assert result["xrefs"] == expected

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("kwargs", "expected_eas"),
    [
        pytest.param({"text": "manalyze"}, [0x1400D6408, 0x1400D65E8], id="text-search"),
        pytest.param({"hex": "6F 75 74 70 75 74 2C 6F"}, [0x1400D61A8], id="hex-search"),
    ],
)
def test_search_results(create_idb, kwargs, expected_eas):
    result = search(**kwargs)
    assert sorted(result["eas"]) == sorted(expected_eas)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        pytest.param({"limit": 3}, {
            "total": 1638,
            "next_offset": 3,
            "items": [
                {
                    "ea": 5369583136,
                    "len": 17,
                    "segment": ".rdata",
                    "encoding": "ascii",
                    "text": "Unknown exception",
                    "text_truncated": False,
                    "sha1": "de24f2d0a243ca2d28955e986528d14a53ed242c"
                },
                {
                    "ea": 5369583208,
                    "len": 20,
                    "segment": ".rdata",
                    "encoding": "ascii",
                    "text": "bad array new length",
                    "text_truncated": False,
                    "sha1": "c3c079b6d2d19707022ad64ce1f44e7e50dc71f6"
                },
                {
                    "ea": 5369583232,
                    "len": 15,
                    "segment": ".rdata",
                    "encoding": "ascii",
                    "text": "string too long",
                    "text_truncated": False,
                    "sha1": "68070eb3d83e80582f9979decc53730976549a3d"
                }
            ]
        }, id="default"),
        pytest.param(
            {
                "limit": 2,
                "offset": 1,
                "min_len": 30,
                "include_xrefs": True,
                "include_text": False
            },
            {
                "total": 519,
                "next_offset": 3,
                "items": [
                    {
                        "ea": 5369584888,
                        "len": 30,
                        "segment": ".rdata",
                        "encoding": "ascii",
                        "xrefs_to": [
                            5368769580
                        ]
                    },
                    {
                        "ea": 5369585048,
                        "len": 39,
                        "segment": ".rdata",
                        "encoding": "ascii",
                        "xrefs_to": [
                            5368794794
                        ]
                    }
                ]
            }, id="pagination"),
    ]
)
def test_list_strings_pagination_and_filters(create_idb, kwargs, expected):
    result = list_strings(**kwargs)
    assert result == expected

