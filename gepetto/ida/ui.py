import random
import string

import idaapi
import ida_hexrays

import gepetto.config
from gepetto.ida.handlers import ExplainHandler, RenameHandler, SwapModelHandler
from gepetto.models.base import GPT4_MODEL_NAME, GPT3_MODEL_NAME, GPT4o_MODEL_NAME, GROQ_MODEL_NAME, MISTRAL_MODEL_NAME


# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/" + _("Explain function")
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/" + _("Rename variables")

    # Model selection menu
    select_gpt35_action_name = "gepetto:select_gpt35"
    select_gpt4_action_name = "gepetto:select_gpt4"
    select_gpt4o_action_name = "gepetto:select_gpt4o"
    select_groq_action_name = "gepetto:select_groq"
    select_mistral_action_name = "gepetto:select_mistral"
    select_gpt35_menu_path = "Edit/Gepetto/" + _("Select model") + f"/OpenAI/{GPT3_MODEL_NAME}"
    select_gpt4_menu_path = "Edit/Gepetto/" + _("Select model") + f"/OpenAI/{GPT4_MODEL_NAME}"
    select_gpt4o_menu_path = "Edit/Gepetto/" + _("Select model") + f"/OpenAI/{GPT4o_MODEL_NAME}"
    select_groq_menu_path = "Edit/Gepetto/" + _("Select model") + f"/Groq/{GROQ_MODEL_NAME}"
    select_mistral_menu_path = "Edit/Gepetto/" + _("Select model") + f"/Together/{GROQ_MODEL_NAME}"

    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    comment = _("Uses {model} to enrich the decompiler's output").format(model=str(gepetto.config.model))
    help = _("See usage instructions on GitHub")
    menu = None

    # -----------------------------------------------------------------------------

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              _('Explain function'),
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              _('Use {model} to explain the currently selected function').format(
                                                  model=str(gepetto.config.model)),
                                              201)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             _('Rename variables'),
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             _("Use {model} to rename this function's variables").format(
                                                 model=str(gepetto.config.model)),
                                             201)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        self.generate_plugin_select_menu()

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    # -----------------------------------------------------------------------------

    def bind_model_switch_action(self, menu_path, action_name, model_name):
        """
        Helper function which facilitates the binding between a menu item and the action
        of switching the selected model.
        :param menu_path: The path associated to the option
        :param action_name: The name of the action
        :param model_name: The name of the model to use when this action is clicked.
        :return: None
        """
        action = idaapi.action_desc_t(action_name,
                                      model_name,
                                      None if str(gepetto.config.model) == model_name
                                      else SwapModelHandler(model_name, self),
                                      "",
                                      "",
                                      208 if str(gepetto.config.model) == model_name else 0)  # Icon #208 == check mark.
        idaapi.register_action(action)
        idaapi.attach_action_to_menu(menu_path, action_name, idaapi.SETMENU_APP)

    # -----------------------------------------------------------------------------

    def detach_actions(self):
        idaapi.detach_action_from_menu(self.select_gpt35_menu_path, self.select_gpt35_action_name)
        idaapi.detach_action_from_menu(self.select_gpt4_menu_path, self.select_gpt4_action_name)
        idaapi.detach_action_from_menu(self.select_gpt4o_menu_path, self.select_gpt4o_action_name)
        idaapi.detach_action_from_menu(self.select_groq_menu_path, self.select_groq_action_name)
        idaapi.detach_action_from_menu(self.select_mistral_menu_path, self.select_mistral_action_name)

    # -----------------------------------------------------------------------------

    def generate_plugin_select_menu(self):
        # Delete any possible previous entries
        idaapi.unregister_action(self.select_gpt35_action_name)
        idaapi.unregister_action(self.select_gpt4_action_name)
        idaapi.unregister_action(self.select_gpt4o_action_name)
        idaapi.unregister_action(self.select_groq_action_name)
        idaapi.unregister_action(self.select_mistral_action_name)
        self.detach_actions()

        # For some reason, IDA seems to have a bug when replacing actions by new ones with identical names.
        # The old action object appears to be reused, at least partially, leading to unwanted behavior?
        # The best workaround I have found is to generate random names each time.
        self.select_gpt35_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"
        self.select_gpt4_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"
        self.select_gpt4o_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"
        self.select_groq_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"
        self.select_mistral_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"

        self.bind_model_switch_action(self.select_gpt35_menu_path, self.select_gpt35_action_name, GPT3_MODEL_NAME)
        self.bind_model_switch_action(self.select_gpt4_menu_path, self.select_gpt4_action_name, GPT4_MODEL_NAME)
        self.bind_model_switch_action(self.select_gpt4o_menu_path, self.select_gpt4o_action_name, GPT4o_MODEL_NAME)
        self.bind_model_switch_action(self.select_groq_menu_path, self.select_groq_action_name, GROQ_MODEL_NAME)
        self.bind_model_switch_action(self.select_mistral_menu_path, self.select_mistral_action_name, MISTRAL_MODEL_NAME)

    # -----------------------------------------------------------------------------

    def run(self, arg):
        pass

    # -----------------------------------------------------------------------------

    def term(self):
        self.detach_actions()
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
