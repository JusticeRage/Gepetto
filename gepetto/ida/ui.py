import random
import string

import idaapi
import ida_hexrays

import gepetto.config
from gepetto.ida.handlers import ExplainHandler, RenameHandler, SwapModelHandler

_ = gepetto.config.translate.gettext

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
    select_gpt4_action_name = "gepetto:select_codellama"
    select_gpt35_menu_path = "Edit/Gepetto/" + _("Select model") + "/gpt-3.5-turbo"
    select_gpt4_menu_path = "Edit/Gepetto/" + _("Select model") + "/gpt-4"
    select_codellama_menu_path = "Edit/Gepetto/" + _("Select model") + "/codellama"

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

    def generate_plugin_select_menu(self):
        # Delete any possible previous entries
        idaapi.unregister_action(self.select_gpt35_action_name)
        idaapi.unregister_action(self.select_gpt4_action_name)
        idaapi.unregister_action(self.select_codellama_action_name)
        idaapi.detach_action_from_menu(self.select_gpt35_menu_path, self.select_gpt35_action_name)
        idaapi.detach_action_from_menu(self.select_gpt4_menu_path, self.select_gpt4_action_name)
        idaapi.detach_action_from_menu(self.select_codellama_menu_path, self.select_codellama_action_name)

        # For some reason, IDA seems to have a bug when replacing actions by new ones with identical names.
        # The old action object appears to be reused, at least partially, leading to unwanted begavior?
        # The best workaround I have found is to generate random names each time.
        self.select_gpt35_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"
        self.select_gpt4_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"
        self.select_codellama_action_name = f"gepetto:{''.join(random.choices(string.ascii_lowercase, k=7))}"

        # Icon #208 is a check mark.
        select_gpt35_action = idaapi.action_desc_t(self.select_gpt35_action_name,
                                                   "gpt-3.5-turbo",
                                                   None if str(gepetto.config.model) == "gpt-3.5-turbo"
                                                   else SwapModelHandler("gpt-3.5-turbo", self),
                                                   "",
                                                   "",
                                                   208 if str(gepetto.config.model) == "gpt-3.5-turbo" else 0)

        idaapi.register_action(select_gpt35_action)
        idaapi.attach_action_to_menu(self.select_gpt35_menu_path, self.select_gpt35_action_name, idaapi.SETMENU_APP)

        # Select gpt-4 action
        select_gpt4_action = idaapi.action_desc_t(self.select_gpt4_action_name,
                                                  "gpt-4",
                                                  None if str(gepetto.config.model) == "gpt-4"
                                                  else SwapModelHandler("gpt-4", self),
                                                  "",
                                                  "",
                                                  208 if str(gepetto.config.model) == "gpt-4" else 0)
        idaapi.register_action(select_gpt4_action)
        idaapi.attach_action_to_menu(self.select_gpt35_menu_path, self.select_gpt4_action_name, idaapi.SETMENU_APP)

        # Select codellama action
        select_codellama_action = idaapi.action_desc_t(self.select_codellama_action_name,
                                                  "codellama",
                                                  None if str(gepetto.config.model) == "codellama"
                                                  else SwapModelHandler("codellama", self),
                                                  "",
                                                  "",
                                                  208 if str(gepetto.config.model) == "codellama" else 0)
        idaapi.register_action(select_codellama_action)
        idaapi.attach_action_to_menu(self.select_gpt35_menu_path, self.select_codellama_action_name, idaapi.SETMENU_APP)

    # -----------------------------------------------------------------------------

    def run(self, arg):
        pass

    # -----------------------------------------------------------------------------

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.select_gpt35_menu_path, self.select_gpt35_action_name)
        idaapi.detach_action_from_menu(self.select_gpt4_menu_path, self.select_gpt4_action_name)
        idaapi.detach_action_from_menu(self.select_codellama_menu_path, self.select_codellama_action_name)
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
