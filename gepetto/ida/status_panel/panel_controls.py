"""Which controls the panel puts in its rows.

Separate from prompt_input for the same reason prompt_sizing is: importing
the widget needs a running Qt, and there is nothing Qt about keeping a list
of the things that want a place in the row.
"""

#: The buttons beside the prompt box, in the order they registered.
_BUILDERS: list = []


def register_prompt_button(build):
    """Add a button to the row beside the prompt box.

    ``build(prompt_input, parent)`` returns the widget, or None to add
    nothing -- which lets a button decide for itself whether it applies,
    rather than the panel having to know when to skip it.

    It is called each time the panel is built rather than once at import, so
    a button whose label depends on state is right when it appears.

    Usable as a decorator. The expand button in prompt_input registers
    through it, so this is how the row is composed and not a side door.
    """
    _BUILDERS.append(build)
    return build


def buttons_for(prompt_input, parent=None):
    """Every registered button, built for this prompt box."""
    built = (build(prompt_input, parent) for build in _BUILDERS)
    return [button for button in built if button is not None]
