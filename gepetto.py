import functools
import json
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import os
import re
import textwrap
import threading

# Set your API key here, or put in in the OPENAI_API_KEY environment variable.
openai.api_key = ""

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/Explain function"
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/Rename variables"
    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    comment = "Uses ChatGPT to enrich the decompiler's output"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Check for whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              'Explain function',
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              'Use ChatGPT to explain the currently selected function',
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             'Rename variables',
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             "Use ChatGPT to rename this function's variables",
                                             199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.explain_menu_path, self.rename_action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.explain_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.rename_action_name, "Gepetto/")

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

class ExplainHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying ChatGPT for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_chatgpt_async("Can you explain what the following C function does and suggest a better name for it?\n"
                            + str(decompiler_output),
                            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

def rename_callback(address, view, response):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from ChatGPT
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        print(f"Error: couldn't extract a response from ChatGPT's output:\n{response}")
        return
    names = json.loads(j.group(0))

    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea

    counter = 0
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            counter += 1
    # Refresh the window to show the new names
    view.refresh_view(True)
    print(f"ChatGPT query finished! {counter} variable(s) renamed.\nPress F5 if the new names don't appear.")

# -----------------------------------------------------------------------------

class RenameHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from ChatGPT and updates the
    decompiler's output.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_chatgpt_async("Analyze the following C function:\n" + str(decompiler_output) +
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names"
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.",
                            functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

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
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].text), ida_kernwin.MFF_WRITE)
    except openai.OpenAIError as e:
        raise print(f"ChatGPT could not complete the request: {str(e)}")

# -----------------------------------------------------------------------------

def query_chatgpt_async(query, cb):
    """
    Function which sends a query to ChatGPT and calls a callback when the response is available.
    :param query: The request to send to ChatGPT
    :param cb: Tu function to which the response will be passed to.
    """
    print("Request to ChatGPT sent...")
    t = threading.Thread(target=query_chatgpt, args=[query, cb])
    t.start()

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    if not openai.api_key:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("Please edit this script to insert your OpenAI API key!")
            raise ValueError("No valid OpenAI API key found")

    return GepettoPlugin()
