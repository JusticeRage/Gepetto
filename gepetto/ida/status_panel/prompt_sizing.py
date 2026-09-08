"""How tall the prompt box should be for what has been typed into it.

Kept apart from the widget deliberately. This is the whole of the behaviour --
start at one line, grow with the text, stop before the panel has no room left
for the conversation, scroll past that -- and it is arithmetic, so it can be
checked. The widget that applies it cannot be: importing it requires a running
Qt, which the test environment does not have.
"""

#: How far it grows before it scrolls instead. Beyond this the panel it lives
#: in has no room left for the conversation, which is the thing being read.
MAX_VISIBLE_LINES = 8


def visible_height(content_lines, line_height, chrome, minimum,
                   max_lines=MAX_VISIBLE_LINES):
    """(height in pixels, whether it now has to scroll).

    ``content_lines`` is the document height in lines, which is what wrapping
    produced rather than what was typed. ``chrome`` is everything that is not
    text: frame, document margin, padding. ``minimum`` is what the row beside
    it asked for, so the box and the buttons line up.
    """
    wanted = int(content_lines * line_height) + chrome
    smallest = max(line_height + chrome, minimum)
    largest = max(line_height * max_lines + chrome, smallest)
    return max(smallest, min(wanted, largest)), wanted > largest
