import functools
import json
import os
import re
import textwrap
import threading
import gettext
import tkinter as tk
import urllib.parse

import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai

# =============================================================================
# EDIT VARIABLES IN THIS SECTION
# =============================================================================

# Set your API key here, or put it in the OPENAI_API_KEY environment variable.
openai.api_key = None
model_to_use = 'gpt-3.5-turbo'
chatsonic_api_key = None
bing_u_cookie = None
rapid_api_key= None
config_path="C:\\Users\\someone\\idapro\\plugins\\"


# Specify the program language. It can be "fr_FR", "zh_CN", or any folder in gepetto-locales.
# Defaults to English.
language = ""

# =============================================================================
# END
# =============================================================================

# Set up translations
translate = gettext.translation('gepetto',
                                os.path.join(os.path.abspath(os.path.dirname(__file__)), "gepetto-locales"),
                                fallback=True,
                                languages=[language])
_ = translate.gettext

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

def read_config():
    global bing_u_cookie
    global model_to_use
    global chatsonic_api_key
    global rapid_api_key

    with open(f"{config_path}gepetto-config.json") as f:
        data = json.load(f)

    openai.api_key = data.get('openai_api_key',None)
    model_to_use = data.get('model_to_use','gpt-3.5-turbo')
    chatsonic_api_key = data.get('chatsonic_api_key',None)
    bing_u_cookie = data.get('bing_u_cookie',None)
    rapid_api_key = data.get('rapid_api_key',None)


class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/Explain function"
    choose_model_action_name= "gepetto:choose_model"
    choose_model_menu_path = "Edit/Gepetto/Choose Model"
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/Rename variables"
    rename_all_sub_action_name="gepetto:rename_all_sub_function"
    rename_all_sub_menu_path="Edit/Gepetto/Rename All sub_ functions"
    vuln_action_name = "gepetto:vuln_function"
    vuln_menu_path = "Edit/Gepetto/Find Possible Vulnerability"
    expl_action_name = "gepetto:expl_function"
    expl_menu_path = "Edit/Gepetto/Write Python Exploit Sample Script"
    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    comment = _(f"Uses {model_to_use} to enrich the decompiler's output")
    help = _("See usage instructions on GitHub")
    menu = None

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              _('Explain function'),
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              _('Use gpt-3.5-turbo to explain the currently selected function'),
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             _('Rename variables'),
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             _("Use gpt-3.5-turbo to rename this function's variables"),
                                             199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        # Model choosing action
        choose_model_action = idaapi.action_desc_t(self.choose_model_action_name,
                                                   'Choose model',
                                                   ChooseModelHandler(),
                                                   None,
                                                   "Choose which model to use: davinci-003 or ChatSonic",
                                                   199)
        idaapi.register_action(choose_model_action)
        idaapi.attach_action_to_menu(self.choose_model_menu_path, self.choose_model_action_name, idaapi.SETMENU_APP)

        # TODO: Rename all sub_ functions action
        # This will rename all small sub_* functions
        # We can itterate across available models so that if one model is down
        # or if we don't have tokens left, we can get output from another
        '''
        rename_all_sub_action = idaapi.action_desc_t(self.rename_all_sub_action_name,
                                                   'Rename all sub_ functions',
                                                   RenameAllSubFunction_handler(),
                                                   None,
                                                   "Apply renaming to all sub_ functions",
                                                   199)
        idaapi.register_action(rename_all_sub_action)
        idaapi.attach_action_to_menu(self.choose_model_menu_path, self.rename_all_sub_action_name, idaapi.SETMENU_APP)
        '''

        #Function vulnerability Checker
        vuln_action = idaapi.action_desc_t(self.vuln_action_name,
                                           'Find possible vulnerability in function',
                                           VulnHandler(),
                                           "Ctrl+Alt+V",
                                           "Use davinci-003 to find possible vulnerability in decompiled function",
                                           199)
        idaapi.register_action(vuln_action)
        idaapi.attach_action_to_menu(self.vuln_menu_path, self.vuln_action_name, idaapi.SETMENU_APP)

        #Function Exploit Creator
        exploit_action = idaapi.action_desc_t(self.expl_action_name,
                                              'Create Sample Python Exploit',
                                              ExploitHandler(),
                                              "Ctrl+Alt+X",
                                              "Use davinci-003 to create a sample exploit script in python",
                                              199)
        idaapi.register_action(exploit_action)
        idaapi.attach_action_to_menu(self.expl_menu_path, self.expl_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.choose_model_menu_path, self.choose_model_action_name)
        #idaapi.detach_action_from_menu(self.rename_all_sub_menu_path, self.rename_all_sub_action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
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
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA, but preserve any existing non-Gepetto comment
    comment = idc.get_func_cmt(address, 0)
    comment = re.sub(r'----- ' + _("Comment generated by Gepetto") + ' -----.*?----------------------------------------',
                     r"",
                     comment,
                     flags=re.DOTALL)

    idc.set_func_cmt(address, '----- ' + _("Comment generated by Gepetto") +
                     f" -----\n\n"
                     f"{response.strip()}\n\n"
                     f"----------------------------------------\n\n"
                     f"{comment.strip()}", 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print(_(f"{model_to_use} query finished!"))


# -----------------------------------------------------------------------------

class ChooseModelHandler(idaapi.action_handler_t):
    """
    This handler is tasked with choosing in between different llm models
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        self.popup()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    def popup(self):
        def option1():
            global model_to_use
            model_to_use = 'gpt-3.5-turbo'
            window.destroy()

        def option2():
            global model_to_use
            model_to_use = 'ChatSonic'
            window.destroy()

        def option3():
            global model_to_use
            model_to_use = 'BINGGPT'
            window.destroy()

        window = tk.Tk()
        window.title("Choose an model")
        window.geometry("200x150")

        label = tk.Label(window, text="Choose a model:")
        label.pack()

        button1 = tk.Button(window, text="gpt-3.5-turbo", command=option1)
        button1.pack(pady=5)

        button2 = tk.Button(window, text="CHATSONIC", command=option2)
        button2.pack(pady=5)

        button3 = tk.Button(window, text="BINGGPT", command=option3)
        button3.pack(pady=5)

        window.mainloop()

# -----------------------------------------------------------------------------

class ExplainHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying a model for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(_("Can you explain what the following C function does and suggest a better name for it?\n"
                            "{decompiler_output}").format(decompiler_output=str(decompiler_output)),
                          functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
class VulnHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying davinci-003 for a possible check of vulneranilities on a given function.
    Once the reply is received its added to the function as a comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Can you find the vulnerabilty in the following C function and suggest the possible way to exploit it?\n"
        + str(decompiler_output),
        functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
# -----------------------------------------------------------------------------
class ExploitHandler(idaapi.action_handler_t):
    """
    This handler requests a python exploit for the vulnerable function
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_ouput = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Find the vulnerability in the following C function:\n" + str(decompiler_ouput) +
        "\nWrite a python one liner to exploit the function",
        functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
# -----------------------------------------------------------------------------

def rename_callback(address, view, response, retries=0):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from gpt-3.5-turbo
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print(_("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
            print(response)
            return
        print(_("Cannot extract valid JSON from the response. Asking the model to fix it..."))
        query_model_async(f"The JSON document provided in this response is invalid. Can you fix it?\n {response}",
                              functools.partial(rename_callback,
                                                address=address,
                                                view=view,
                                                retries=retries + 1))
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:  # Give up fixing the JSON after 3 times.
            print(_("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
            print(response)
            return
        print(_("The JSON document returned is invalid. Asking the model to fix it..."))
        query_model_async(_("Please fix the following JSON document:\n{json}").format(json=j.group(0)),
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1))
        return

    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea

    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print(_(f"{model_to_use} query finished! {replaced} variable(s) renamed.").format(replaced=len(replaced)))

# -----------------------------------------------------------------------------

class RenameHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from model and updates the
    decompiler's output.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(_("Analyze the following C function:\n{decompiler_output}"
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names "
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.").format(decompiler_output=str(decompiler_output)),
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# =============================================================================
# gpt-3.5-turbo interaction
# =============================================================================

def query_model(query, cb, max_tokens=2500):
    """
    Function which sends a query to gpt-3.5-turbo and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to gpt-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": query}
            ]
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0]["message"]["content"]),
                                 ida_kernwin.MFF_WRITE)
    except openai.InvalidRequestError as e:
        # Context length exceeded. Determine the max number of tokens we can ask for and retry.
        m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                      r'prompt;', str(e))
        if not m:
            print(_("gpt-3.5-turbo could not complete the request: {error}").format(error=str(e)))
            return
        (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
        max_tokens = hard_limit - prompt_tokens
        if max_tokens >= 750:
            print(_("Context length exceeded! Reducing the completion tokens to "
                    "{max_tokens}...").format(max_tokens=max_tokens))
            query_model(query, cb, max_tokens)
        else:
            print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")

    except openai.OpenAIError as e:
        print(_("gpt-3.5-turbo could not complete the request: {error}").format(error=str(e)))
    except Exception as e:
        print(_("General exception encountered while running the query: {error}").format(error=str(e)))

# =============================================================================
# BING interaction
# =============================================================================
def set_bing_u_cookie():
    global bing_u_cookie
    bing_u_cookie = ida_kernwin.ask_str("Enter your bing_u cookie")

def query_bing_model(query, cb, max_tokens=2500):
    """
    Function which sends a query to BING GPT and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to BING GPT
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        url = "https://chatgpt-4-bing-ai-chat-api.p.rapidapi.com/chatgpt-4-bing-ai-chat-api/0.2/send-message/"

        # check if the query has previous bing GPT comments in the function
        if('{"message":' in query and 'Suggest better variable names' in query):
            # We strip query from that comment
            query = "{".join(query.split('}')[1:])
        # Unfortunately, input is limited to 600 chars so we truncate the query
        # if above
        if(len(query)>600):
            query = query[:598]

        payload = f"bing_u_cookie={bing_u_cookie}&question={urllib.parse.quote(query)}"
        print(payload)
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "X-RapidAPI-Key": f"{rapid_api_key}",
            "X-RapidAPI-Host": "chatgpt-4-bing-ai-chat-api.p.rapidapi.com"
        }

        response = requests.post(url, data=payload, headers=headers)
        bing_res = response.text
        if('Input bing_u_cookie is not valid' in bing_res):
            set_bing_u_cookie()
            raise Exception
        if(response.status_code!=200):
            raise Exception
        parsed_json = json.loads(bing_res)
        text_response = parsed_json[0]['text_response']
        if('Suggest better variable names' in query):
            # Just grab the json from the response:
            res_dic = json.loads(response.text)
            bing_res = res_dic['message']

        print(text_response)
        ida_kernwin.execute_sync(functools.partial(cb, response=text_response), ida_kernwin.MFF_WRITE)

    except:
        print(bing_res)
        print("Bing GPT error")

# =============================================================================
# chatsonic interaction
# =============================================================================

def query_sonic_model(query, cb, max_tokens=2500):
    """
    Function which sends a query to chatsonic and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to chatsonic
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        url = "https://api.writesonic.com/v2/business/content/chatsonic?engine=premium&language=en"

        # check if the query has previous chatsonic comments in the function
        if('{"message":' in query and 'Suggest better variable names' in query):
            # We strip query from that comment
            query = "{".join(query.split('}')[1:])
        # Unfortunately, input is limited to 600 chars so we truncate the query
        # if above
        if(len(query)>600):
            query = query[:598]
        payload = {
            "enable_google_results": "true",
            "enable_memory": False,
            "input_text": f"{query}"
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "X-API-KEY": f"{chatsonic_api_key}"
        }

        print(payload)

        response = requests.post(url, json=payload, headers=headers)
        chatson_res = response.text
        if('This feature needs at least 1 word(s) but you only have 0' in chatson_res or response.status_code!=200):
            raise Exception
        if('Suggest better variable names' in query):
            # Just grab the json from the response:
            res_dic = json.loads(response.text)
            chatson_res = res_dic['message']
        print(chatson_res)
        ida_kernwin.execute_sync(functools.partial(cb, response=chatson_res), ida_kernwin.MFF_WRITE)

    except:
        print(response.text)
        print("ChatSonic error")


# -----------------------------------------------------------------------------

def query_model_async(query, cb):
    """
    Function which sends a query to model and calls a callback when the response is available.
    :param query: The request to send to model
    :param cb: Tu function to which the response will be passed to.
    """
    print(_(f"Request to {model_to_use} sent..."))
    t = threading.Thread(target=model_lookup[model_to_use], args=[query, cb])
    t.start()

# Model map

model_lookup = {'gpt-3.5-turbo': query_model,
                'CHATSONIC': query_sonic_model,
                'BINGGPT': query_bing_model
                }

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    read_config()
    if not openai.api_key:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print(_("Please edit the gepetto-config to insert your OpenAI API key!"))
            raise ValueError("No valid OpenAI API key found")

    return GepettoPlugin()
