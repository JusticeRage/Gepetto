import pytest

import gepetto.ida.utils.function_helpers

def test_resolve_name(create_idb):
    assert gepetto.ida.utils.function_helpers.resolve_ea("main")  == 0x140017F60
