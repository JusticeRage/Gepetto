"""How tall the prompt box gets, and when it gives up and scrolls.

The widget itself needs a running Qt, which the test environment does not have,
so the rule it follows lives in a function that takes numbers. That rule is the
feature: start at one line, grow with the text, stop before the panel has no
room left for the conversation, and only then scroll.

Heights below are in pixels with a 20px line and 10px of chrome (frame,
document margin, padding), which keeps the arithmetic legible.
"""

from gepetto.ida.status_panel.prompt_sizing import MAX_VISIBLE_LINES, visible_height

LINE = 20
CHROME = 10


def height(lines, minimum=0, max_lines=MAX_VISIBLE_LINES):
    return visible_height(lines, LINE, CHROME, minimum, max_lines)


def test_an_empty_box_is_one_line_tall():
    assert height(1) == (LINE + CHROME, False)


def test_it_grows_a_line_at_a_time():
    assert height(2)[0] == 2 * LINE + CHROME
    assert height(3)[0] == 3 * LINE + CHROME


def test_it_stops_growing_at_the_limit():
    """Past this the panel has no room left for the conversation, which is the
    thing being read."""
    tallest = MAX_VISIBLE_LINES * LINE + CHROME

    assert height(MAX_VISIBLE_LINES)[0] == tallest
    assert height(MAX_VISIBLE_LINES + 5)[0] == tallest
    assert height(500)[0] == tallest


def test_a_scrollbar_appears_only_once_it_has_stopped_growing():
    assert height(MAX_VISIBLE_LINES)[1] is False
    assert height(MAX_VISIBLE_LINES + 1)[1] is True


def test_a_box_that_still_fits_never_scrolls():
    assert all(height(lines)[1] is False
               for lines in range(1, MAX_VISIBLE_LINES + 1))


# --- lining up with the buttons beside it ------------------------------------

def test_a_minimum_keeps_it_level_with_the_buttons():
    """align_row passes the button height so the row does not look assembled."""
    button = LINE + CHROME + 8

    assert height(1, minimum=button)[0] == button


def test_the_minimum_does_not_stop_it_growing():
    button = LINE + CHROME + 8

    assert height(4, minimum=button)[0] == 4 * LINE + CHROME


def test_a_minimum_taller_than_the_limit_still_wins():
    """Nothing here should ever return a height that hides the caret."""
    absurd = 1000

    tall, scrolls = height(1, minimum=absurd)

    assert tall == absurd
    assert scrolls is False


def test_a_fractional_content_height_is_not_rounded_up_into_a_scrollbar():
    """Qt reports document height as a float; a box holding exactly the limit
    must not tip into scrolling because of it."""
    assert height(float(MAX_VISIBLE_LINES))[1] is False
