import functools
import random
import string
import threading

import idaapi
import ida_hexrays
import ida_kernwin

import gepetto.config
from gepetto.ida.handlers import ExplainHandler, RenameHandler, SwapModelHandler
from gepetto.ida.cli import register_cli
import gepetto.models.model_manager


# =============================================================================
# Setup the menus, hotkeys and cli in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/" + _("Explain function")
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/" + _("Rename variables")
    wanted_name = 'Gepetto'
    wanted_hotkey = ''
    comment = _("Uses {model} to enrich the decompiler's output").format(model=str(gepetto.config.model))
    help = _("See usage instructions on GitHub")
    menu = None
    model_action_map = {}

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

        self.generate_model_select_menu()

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        # Register CLI
        register_cli()

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
        ida_kernwin.execute_sync(functools.partial(idaapi.register_action, action), ida_kernwin.MFF_FAST)
        ida_kernwin.execute_sync(functools.partial(idaapi.attach_action_to_menu, menu_path, action_name, idaapi.SETMENU_APP),
                                 ida_kernwin.MFF_FAST)

    # -----------------------------------------------------------------------------

    def detach_actions(self):
        for provider in gepetto.models.model_manager.list_models():
            for model in provider.supported_models():
                if model in self.model_action_map:
                    ida_kernwin.execute_sync(functools.partial(idaapi.unregister_action, self.model_action_map[model]),
                                             ida_kernwin.MFF_FAST)
                    ida_kernwin.execute_sync(functools.partial(idaapi.detach_action_from_menu,
                                                               "Edit/Gepetto/" + _("Select model") +
                                                               f"/{provider.get_menu_name()}/{model}",
                                                               self.model_action_map[model]),
                                             ida_kernwin.MFF_FAST)

    # -----------------------------------------------------------------------------

    def generate_model_select_menu(self):
        def do_generate_model_select_menu():
            # Delete any possible previous entries
            self.detach_actions()

            for provider in gepetto.models.model_manager.list_models():
                for model in provider.supported_models():
                    # For some reason, IDA seems to have a bug when replacing actions by new ones with identical names.
                    # The old action object appears to be reused, at least partially, leading to unwanted behavior?
                    # The best workaround I have found is to generate random names each time.
                    self.model_action_map[model] = f"gepetto:{model}_{''.join(random.choices(string.ascii_lowercase, k=7))}"
                    self.bind_model_switch_action("Edit/Gepetto/" + _("Select model") + f"/{provider.get_menu_name()}/{model}",
                                                  self.model_action_map[model],
                                                  model)
        # Building the list of available models can take a few seconds with Ollama, don't hang the UI.
        threading.Thread(target=do_generate_model_select_menu).start()

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
