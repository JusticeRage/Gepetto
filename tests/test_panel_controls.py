"""Which controls the panel builds, and in what order.

The registries are plain lists and pure functions, which is why they live
outside the widget modules: importing one of those needs a running Qt and
the test environment has none.
"""

from gepetto.ida.status_panel import panel_controls


# --- which buttons sit beside the box ----------------------------------------

def test_a_registered_button_joins_the_row_in_order():
    
    original = list(panel_controls._BUILDERS)
    try:
        panel_controls._BUILDERS.clear()
        panel_controls.register_prompt_button(lambda box, parent=None: f"first:{box}")
        panel_controls.register_prompt_button(lambda box, parent=None: f"second:{box}")
        assert panel_controls.buttons_for("BOX") == ["first:BOX", "second:BOX"]
    finally:
        panel_controls._BUILDERS[:] = original


def test_a_button_that_returns_none_leaves_itself_out():
    """So a button decides whether it applies, not the panel."""
    
    original = list(panel_controls._BUILDERS)
    try:
        panel_controls._BUILDERS.clear()
        panel_controls.register_prompt_button(lambda box, parent=None: None)
        panel_controls.register_prompt_button(lambda box, parent=None: "kept")
        assert panel_controls.buttons_for("BOX") == ["kept"]
    finally:
        panel_controls._BUILDERS[:] = original


def test_register_prompt_button_returns_what_it_was_given():
    """It is meant to be used as a decorator, which requires this."""
    
    original = list(panel_controls._BUILDERS)
    try:
        def build(box, parent=None):
            return box
        assert panel_controls.register_prompt_button(build) is build
    finally:
        panel_controls._BUILDERS[:] = original


def test_the_panels_own_button_registers_through_the_same_door():
    """The registry has an in-tree caller, which is what makes it a seam and
    not scaffolding.

    Read from the source rather than by importing: prompt_input needs a
    running Qt, which is exactly why the registry does not live in it.
    """
    import ast
    import pathlib

    source = pathlib.Path("gepetto/ida/status_panel/prompt_input.py").read_text()
    decorated = {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef)
        and any(getattr(d, "id", None) == "register_prompt_button"
                for d in node.decorator_list)
    }
    assert "expand_button" in decorated
