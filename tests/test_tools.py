from typing import Any

import pytest
import uuid

import ida_bytes
import idc

from gepetto.ida.utils import function_helpers
from gepetto.ida.tools import (
    declare_c_type,
    decompile_function,
    get_bytes,
    get_disasm,
    get_struct,
    get_xrefs,
    list_functions,
    list_imports,
    rename_function,
    search,
    set_comment,
    disasm_function,
)


@pytest.fixture
def main_ea(create_idb):
    return function_helpers.resolve_ea("main")


@pytest.fixture
def comment_context(main_ea):
    original = idc.get_func_cmt(main_ea, 0) or ""
    yield main_ea, original
    idc.set_func_cmt(main_ea, original, 0)


@pytest.fixture
def imports_snapshot(create_idb):
    snapshot = list_imports.list_imports(limit=64)
    if not snapshot["items"]:
        pytest.skip("No imports discovered in the sample database.")
    return snapshot


@pytest.fixture
def function_pages(create_idb):
    return {
        include: _collect_all_functions(include)
        for include in (True, False)
    }


@pytest.fixture
def unique_struct_name():
    return f"gp_test_{uuid.uuid4().hex[:8]}"


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
    ("target_name", "expected_ea"),
    [
        pytest.param("sub_1400D38F0", 0x1400D38F0, id="function"),
        pytest.param("??_7_Facet_base@std@@6B@", 0x1400D57D0, id="const"),
    ],
)
def test_resolve_ea(create_idb, target_name, expected_ea):
    ea = function_helpers.resolve_ea(target_name)
    assert ea == expected_ea

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
    result = get_disasm.get_disasm(ea)

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
    result = get_bytes.get_bytes(ea, size)

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
        pytest.param("main", "manalyze.conf", id="main"),
    ],
)
def test_get_function_code(create_idb, target_name, expected_fragment):
    result = decompile_function.decompile_function(name=target_name)
    assert expected_fragment in str(result)

# ---------------------------------------------------------------------------

def test_list_imports_pagination_and_filter(imports_snapshot):
    total = imports_snapshot["total"]
    items = imports_snapshot["items"]
    assert total >= len(items)

    next_offset = imports_snapshot.get("next_offset")
    if next_offset is not None:
        follow_up = list_imports.list_imports(limit=len(items), offset=next_offset)
        assert follow_up["total"] == total
    else:
        assert len(items) == total

    sample = items[0]
    assert isinstance(sample["ea"], int)
    assert isinstance(sample["name"], str)
    assert isinstance(sample["module"], str)

# ---------------------------------------------------------------------------

@pytest.mark.parametrize("normalizer", [str.lower, str.upper], ids=["lower", "upper"])
def test_list_imports_module_filter(imports_snapshot, normalizer):
    module = next((item["module"] for item in imports_snapshot["items"] if item["module"]), None)
    if module is None:
        pytest.skip("Sample database does not expose module names.")

    filtered = list_imports.list_imports(limit=imports_snapshot["total"], module_filter=normalizer(module))
    assert filtered["total"] == len(filtered["items"])
    assert all(module.lower() in entry["module"].lower() for entry in filtered["items"])

# ---------------------------------------------------------------------------

def _collect_all_functions(include_thunks: bool) -> tuple[int, list[dict[str, object]]]:
    collected: list[dict[str, object]] = []
    seen_offsets: set[int] = set()
    offset = 0
    total = None

    while True:
        page = list_functions.list_functions(limit=128, offset=offset, include_thunks=include_thunks)
        if total is None:
            total = page["total"]
        else:
            assert total == page["total"]

        collected.extend(page["items"])
        next_offset = page["next_offset"]
        if next_offset is None:
            break
        assert next_offset not in seen_offsets
        seen_offsets.add(next_offset)
        offset = next_offset

    return total or 0, collected


@pytest.mark.parametrize("include_thunks", [True, False], ids=["with-thunks", "without-thunks"])
def test_list_functions_pagination(function_pages, include_thunks):
    total, funcs = function_pages[include_thunks]
    assert total == len(funcs)
    assert all(isinstance(item["ea"], int) and isinstance(item["name"], str) for item in funcs)


def test_list_functions_thunk_filtering(function_pages):
    total_with, funcs_with = function_pages[True]
    total_without, funcs_without = function_pages[False]

    assert total_without <= total_with
    assert len(funcs_with) == total_with

    names_with = {item["name"] for item in funcs_with}
    assert "main" in names_with

    names_without = {item["name"] for item in funcs_without}
    assert names_without.issubset(names_with)

# ---------------------------------------------------------------------------

def test_set_comment_round_trip(comment_context):
    ea, _ = comment_context
    new_comment = "gepetto test comment\nsecond line"

    result = set_comment.set_comment(ea=ea, comment=new_comment)
    assert result["ok"] is True
    assert result["ea"] == ea
    round_trip = idc.get_func_cmt(ea, 0) or ""
    assert round_trip == new_comment.rstrip("\r\n")

# ---------------------------------------------------------------------------

def test_declare_c_type_and_get_struct(create_idb, unique_struct_name):
    struct_name = unique_struct_name
    decl = f"struct {struct_name} {{ int a; int b; }};"

    first = declare_c_type.declare_c_type(decl)
    assert first["success"] is True
    assert first["type_name"] == struct_name

    second = declare_c_type.declare_c_type(decl)
    assert second["success"] is True

    struct_info = get_struct.get_struct(struct_name)
    assert struct_info["name"].endswith(struct_name)
    assert struct_info["size"] >= 8

    fields = {field["name"]: field for field in struct_info["fields"]}
    assert {"a", "b"} <= fields.keys()
    assert fields["a"]["offset"] == 0
    assert fields["b"]["offset"] >= 4

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
        result = rename_function.rename_function(ea=ea, new_name=new_name)
        return result, original_name

    yield _rename

    while to_restore:
        ea, original_name = to_restore.pop()
        rename_function.rename_function(ea=ea, new_name=original_name)


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
    result = get_xrefs.get_xrefs_unified(scope=scope, subject=subject, direction=direction, **kwargs)

    assert result["scope"] == scope
    assert result["direction"] == direction
    assert result["xrefs"] == expected

# ---------------------------------------------------------------------------

def test_get_xrefs_consistency(create_idb):
    name_res = get_xrefs.get_xrefs_unified(scope="name", subject="main", direction="to", only_calls=True)
    func_res = get_xrefs.get_xrefs_unified(scope="function", subject="0x140017F70", direction="to", only_calls=True)
    ea_res = get_xrefs.get_xrefs_unified(scope="ea", subject="0x140017F60", direction="to", only_calls=True)
    del name_res["scope"]
    del func_res["scope"]
    del ea_res["scope"]

    assert name_res == func_res
    assert name_res == ea_res

# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("kwargs", "expected_eas"),
    [
        pytest.param({"text": "manalyze"}, [0x1400D6408, 0x1400D65E8], id="text-search"),
        pytest.param({"hex": "6F 75 74 70 75 74 2C 6F"}, [0x1400D61A8], id="hex-search"),
    ],
)
def test_search_results(create_idb, kwargs, expected_eas):
    result = search.search(**kwargs)
    assert sorted(result["eas"]) == sorted(expected_eas)

# ---------------------------------------------------------------------------

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
    result = search.list_strings(**kwargs)
    assert result == expected

def test_get_disasm_function(create_idb):
    res = disasm_function.disasm_function(name="sub_140060FC0")
    res = res["disasm"]
    assert res == """0x140060fc0: sub     rsp, 28h
0x140060fc4: call    sub_140062890
0x140060fc9: mov     rcx, rax
0x140060fcc: add     rsp, 28h
0x140060fd0: jmp     sub_1400608C0"""
