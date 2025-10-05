import functools
import json
import re
import time
import textwrap
from urllib import response

import idaapi
import ida_hexrays
import ida_kernwin
import idc

import gepetto.config
from gepetto.ida.status_panel import LogCategory, LogLevel, get_status_panel

_ = gepetto.config._

STATUS_PANEL = get_status_panel()

# -----------------------------------------------------------------------------

class CommentHandler(idaapi.action_handler_t):
    """
    This handler queries the model to generate a comment for the
    selected function. Once the reply is received, it is added
    as a function comment.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        start_time = time.time()
        localization_locale = gepetto.config.get_localization_locale()
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        
        pseudocode_lines = get_commentable_lines(decompiler_output)
        formatted_lines = format_commentable_lines(pseudocode_lines)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
              
        gepetto.config.model.query_model_async(
            f"""
                RESPOND STRICTLY IN THE FORMAT JSON MAP {{ lineNumber: "comment" }}, NOTHING ELSE!!!
                Respond in [{localization_locale}] locale.
                Add comments that explain what is happening in this C function.
                You can ONLY add comments to lines that start with a '+'!
                DON'T comment trivial or obvious actions; comment on important or non-obvious blocks; read ENTIRE logical blocks before make a comment.
                \n
                ```C
                {formatted_lines}
                ```
              """,
            functools.partial(comment_callback, decompiler_output=decompiler_output, pseudocode_lines=pseudocode_lines, view=v, start_time=start_time),
            additional_model_options={"response_format": {"type": "json_object"}})
        request_sent = STATUS_PANEL.log_request_started()
        print(request_sent)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

def comment_callback(decompiler_output, pseudocode_lines, view, response, start_time):
    """Callback that sets comments returned by the model at given lines.

    The ``response`` parameter can either be a raw string or a message object
    returned by the OpenAI API.  This keeps compatibility with older behaviour
    while enabling tool-based interactions that return message objects.
    """
    try:
        elapsed_time = time.time() - start_time

        response_text = response.content if hasattr(response, "content") else response

        print(f"Response: {response_text}")

        items = json.loads(response_text)

        applied = 0

        for line_key, raw_comment in items.items():
            try:
                line_index = int(line_key)
            except (TypeError, ValueError):
                continue

            if line_index < 0 or line_index >= len(pseudocode_lines):
                continue

            comment_address = pseudocode_lines[line_index][2]
            comment_placement = pseudocode_lines[line_index][3]
            if comment_placement is None:
                comment_placement = idaapi.ITP_SEMI

            if comment_address is None or comment_address == idaapi.BADADDR:
                continue

            comment_text = str(raw_comment).strip()
            if not comment_text:
                continue

            target = idaapi.treeloc_t()
            target.ea = int(comment_address)
            target.itp = comment_placement
            decompiler_output.set_user_cmt(target, comment_text)
            applied += 1

        decompiler_output.save_user_cmts()
        decompiler_output.del_orphan_cmts()

        if view:
            view.refresh_view(True)

        if applied:
            STATUS_PANEL.log(
                _("Applied {count} comments.").format(count=applied),
                category=LogCategory.TOOL,
                level=LogLevel.SUCCESS,
            )
        else:
            STATUS_PANEL.log(
                _("No comments were applied."),
                category=LogCategory.TOOL,
            )

        response_finished = STATUS_PANEL.log_request_finished(elapsed_time)
        print(response_finished)

    except Exception as e:
        error_message = _("[ERROR] comment_callback: {error}").format(error=e)
        print(error_message)
        STATUS_PANEL.mark_error(error_message)
        raise


# -----------------------------------------------------------------------------

def get_commentable_lines(cfunc):
    """
    Extracts information for each line of decompiled pseudocode, including:
      - lineIndex: Line number in the pseudocode listing (starting from 0).
      - lineText: Cleaned text of the line (IDA formatting tags removed).
      - comment_address: Address in the decompiled function suitable for attaching a comment, or BADADDR if unavailable.
      - comment_placement: Comment placement type (e.g., ITP_SEMI, ITP_COLON), or 0 if unavailable.
      - has_user_comment: True if a user comment already exists for this line, otherwise False.

    Args:
        cfunc (idaapi.cfuncptr_t): Decompiled function object.

    Returns:
        List of tuples: (lineIndex, lineText, comment_address, comment_placement, has_user_comment)
    """
    result = []

    pseudocode_lines = cfunc.get_pseudocode()
    
    place_comments_above = (gepetto.config.get_config("Gepetto", "COMMENT_POSITION", default="above") == "above")

    for idx, line in enumerate(pseudocode_lines):
        # Clean line text from formatting tags
        try:
            line_text = idaapi.tag_remove(line.line)
        except Exception:
            line_text = str(line.line)

        # Lookup ctree item
        phead = idaapi.ctree_item_t()
        pitem = idaapi.ctree_item_t()
        ptail = idaapi.ctree_item_t()

        phead_addr = None
        phead_place = None
        ptail_addr = None
        ptail_place = None
        
        has_user_comment = False
        comment_address = None
        comment_placement = 0

        found = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
        if found:
            # Invert preferred locations order
            if not place_comments_above:
                tmp = phead
                phead = ptail
                ptail = tmp
                
            # Assign locations if available and valid
            if hasattr(phead, "loc") and phead.loc and phead.loc.ea != idaapi.BADADDR:
                has_user_comment |= (cfunc.get_user_cmt(phead.loc, True) is not None)
                phead_addr = phead.loc.ea
                phead_place = phead.loc.itp
            if hasattr(ptail, "loc") and ptail.loc and ptail.loc.ea != idaapi.BADADDR:
                has_user_comment |= (cfunc.get_user_cmt(ptail.loc, True) is not None)
                ptail_addr = ptail.loc.ea
                ptail_place = ptail.loc.itp

            # Pick final address and placement (prefer phead if present)
            if phead_addr is not None:
                comment_address = phead_addr
                comment_placement = phead_place
            elif ptail_addr is not None:
                comment_address = ptail_addr
                comment_placement = ptail_place

        result.append((idx, idaapi.tag_remove(line_text), comment_address, comment_placement, has_user_comment))

    return result

# -----------------------------------------------------------------------------

def format_commentable_lines(commentable_lines):
    """
    Formats the output of get_commentable_lines() for display.

    For each line:
      - Adds a "+" before the index if a comment address exists and the line does not already have a user comment.
      - Formats as: [+]index<TAB>text

    Args:
        commentable_lines: List of tuples (index, text, comment_address, comment_placement, has_user_comment)

    Returns:
        str: The formatted text as a single string, with one line per entry.
    """
    output = []
    for idx, text, comment_address, comment_placement, has_user_comment in commentable_lines:
        
        # Add "+" if the line can be commented and has no user comment yet
        prefix = "+" if comment_address is not None and not has_user_comment else ""
        
        output.append(f"{prefix}{idx}\t{text}")
    return "\n".join(output)

# -----------------------------------------------------------------------------

