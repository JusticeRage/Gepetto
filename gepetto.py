import functools
import idaapi
import ida_hexrays
import idc
import openai
import textwrap
import threading

openai.api_key = ""

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    action_name = "gepetto:explain_function"
    menu_path = "Edit/Gepetto/Explain function"
    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    menu = None

    def init(self):
        action_desc = idaapi.action_desc_t(
            self.action_name,               # The action name. This acts like an ID and must be unique
            'Explain function',             # The action text.
            GepettoHandler(),               # The action handler.
            "Ctrl+Alt+G",                   # Optional: the action shortcut
            'Use ChatGPT to explain the currently selected function',  # Optional: the action tooltip (available in menus/toolbar)
            199)                            # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(
            self.menu_path,                 # The relative path of where to add the action
            self.action_name,               # The action ID (see above)
            idaapi.SETMENU_APP)             # We want to append the action after the 'Manual instruction...'

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.menu_path, self.action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA.
    idc.set_func_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    view.refresh_view(False)
    print("ChatGPT query finished!")


# -----------------------------------------------------------------------------

class GepettoHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_chatgpt_async("Can you explain what the following C function does?\n" + str(decompiler_output) +
                            "\nSuggest better name for the function and its arguments.",
                            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.action_name, "Gepetto/")

# =============================================================================
# ChatGPT interaction
# =============================================================================

def query_chatgpt(query, cb):
    """
    Function which sends a query to ChatGPT and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to ChatGPT
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=query,
            temperature=0.6,
            max_tokens=2500,
            top_p=1,
            frequency_penalty=1,
            presence_penalty=1
        )
        cb(response=response.choices[0].text)
    except openai.error as e:
        raise print(f"ChatGPT could not complete the request: {str(e)}")


def query_chatgpt_async(query, cb):
    """
    Function which sends a query to ChatGPT and calls a callback when the response is available.
    :param query: The request to send to ChatGPT
    :param cb: Tu function to which the response will be passed to.
    """
    print("Request to ChatGPT sent...")
    t = threading.Thread(target=query_chatgpt, args=[query, cb])
    # Ideally, this would be t.start() and the thread would run in the background.
    # Unfortunately, set_func_cmt can only be called from the main thread :(
    # TODO: find a fix
    t.run()

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    if not openai.api_key:
        print("Please edit this script to insert your OpenAI API key!")
        raise ValueError("No valid OpenAI API key found")

    return GepettoPlugin()
