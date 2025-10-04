import pytest
import warnings

# Silence IDA SWIG types missing __module__ on Py 3.13 (before IDA imports)
warnings.filterwarnings(
    "ignore",
    message=r"builtin type (SwigPyPacked|SwigPyObject|swigvarlink) has no __module__ attribute",
    category=DeprecationWarning,
    module=r"importlib\._bootstrap",
)

import idapro
import ida_auto

@pytest.fixture(scope="session")
def create_idb():
    idapro.open_database("tests/testfiles/manalyze.exe", True)
    ida_auto.auto_wait()
    yield
    idapro.close_database()
