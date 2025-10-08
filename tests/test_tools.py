import pytest

import gepetto.ida.utils.function_utils

def test_resolve_name(create_idb):
    assert gepetto.ida.utils.function_utils.resolve_ea("main")  == 0x140017F60
