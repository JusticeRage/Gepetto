import functools
import os
import random
import string
import threading

import idaapi
import ida_hexrays
import ida_kernwin

import gepetto.config
from gepetto.ida.handlers import ExplainHandler, RenameHandler, SwapModelHandler, GenerateCCodeHandler, GeneratePythonCodeHandler
from gepetto.ida.comment_handler import CommentHandler
from gepetto.ida.cli import register_cli
from gepetto.ida.status_panel import panel as STATUS
import gepetto.models.model_manager

_ = gepetto.config._

# Use PySide6 exclusively (IDA 9.x). Do not mix bindings.
try:
    from PySide6 import QtWidgets, QtCore, QtGui  # type: ignore
except Exception:
    QtWidgets = QtCore = QtGui = None  # Fallback to console-only logging


class DockingHooks(idaapi.UI_Hooks):
    def ready_to_run(self):
        STATUS.ensure_shown()
        STATUS.dock()


# =============================================================================
# Setup the menus, hotkeys and cli in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/" + _("Explain function")
    comment_action_name = "gepetto:comment_function"
    comment_menu_path = "Edit/Gepetto/" + _("Comment function")
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/" + _("Auto-rename")
    c_code_action_name = "gepetto:generate_c_code"
    c_code_menu_path = "Edit/Gepetto/" + _("Generate C Code")
    python_code_action_name = "gepetto:generate_python_code"
    python_code_menu_path = "Edit/Gepetto/" + _("Generate Python Code")
    show_status_action_name = "gepetto:show_status_panel"
    show_status_menu_path = "Edit/Gepetto/" + _("Show status panel")
    toggle_parallel_action_name = "gepetto:toggle_parallel_tool_calls"
    toggle_parallel_menu_path = "Edit/Gepetto/" + _("Parallel tool calls")
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
        # Only launch in interactive mode
        if not ida_kernwin.is_idaq():
            return idaapi.PLUGIN_SKIP
        # Check if Gepetto loaded at least one model properly
        if not gepetto.config.model:
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              _('Explain function'),
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              _('Use {model} to explain the currently selected function').format(
                                                  model=str(gepetto.config.model)),
                                              452)
        idaapi.register_action(explain_action)

        # Function commenting action
        comment_action = idaapi.action_desc_t(self.comment_action_name,
                                              _('Comment function'),
                                              CommentHandler(),
                                              "Ctrl+Alt+K",
                                              _('Adds comments to lines in the current function using {model}').format(
                                                  model=str(gepetto.config.model)),
                                              453)
        idaapi.register_action(comment_action)

        # Variable and function renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             _('Auto-rename'),
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             _("Use {model} to auto-rename this function and its variables").format(
                                                 model=str(gepetto.config.model)),
                                             19)
        idaapi.register_action(rename_action)

        # Generate Python Code action
        generate_python_code_action = idaapi.action_desc_t(
            self.python_code_action_name,
            _('Generate Python Code'),
            GeneratePythonCodeHandler(),
            "Ctrl+Alt+P",
            _("Generate python code from the currently selected function using {model}").format(
                model=str(gepetto.config.model)
            ),
            201
        )
        idaapi.register_action(generate_python_code_action)

        # Generate C Code action
        generate_c_code_action = idaapi.action_desc_t(
            self.c_code_action_name,
            _('Generate C Code'),
            GenerateCCodeHandler(),
            "Ctrl+Alt+C",
            _("Generate executable C code from the currently selected function using {model}").format(
                model=str(gepetto.config.model)
            ),
            200
        )
        idaapi.register_action(generate_c_code_action)

        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.comment_menu_path, self.comment_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
        # Status panel action
        show_status_action = idaapi.action_desc_t(
            self.show_status_action_name,
            _("Show status panel"),
            _ShowStatusPanelHandler(),
            "Ctrl+Alt+S",
            _("Open the Gepetto status/log panel"),
            77,
        )
        idaapi.register_action(show_status_action)
        idaapi.attach_action_to_menu(self.show_status_menu_path, self.show_status_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.c_code_menu_path, self.c_code_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.python_code_menu_path, self.python_code_action_name, idaapi.SETMENU_APP)

        self.generate_model_select_menu()
        # Register/refresh the Parallel Tool Calls toggle next to "Select model"
        try:
            self.register_or_update_parallel_action()
        except Exception as e:
            try:
                print(f"Failed to register parallel tool calls toggle: {e}")
            except Exception:
                pass

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        # Docking hook
        self.docking_hook = DockingHooks()
        self.docking_hook.hook()

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

    def _parallel_toggle_state(self) -> bool:
        try:
            v = gepetto.config.get_config("OpenAI", "PARALLEL_TOOL_CALLS", default="false")
            return str(v).strip().lower() in ("1", "true", "yes", "on")
        except Exception:
            return False

    def register_or_update_parallel_action(self):
        """(Re)register the toggle action with a checkmark reflecting state."""
        # Unregister first to refresh icon based on state
        try:
            ida_kernwin.execute_sync(
                functools.partial(idaapi.unregister_action, self.toggle_parallel_action_name),
                ida_kernwin.MFF_FAST,
            )
        except Exception:
            pass

        enabled = self._parallel_toggle_state()
        icon_id = 208 if enabled else 0  # 208 == check mark
        action = idaapi.action_desc_t(
            self.toggle_parallel_action_name,
            _('Parallel tool calls'),
            ToggleParallelToolCallsHandler(self),
            "",
            _('Allow multiple tools to run in parallel (experimental).'),
            icon_id,
        )
        ida_kernwin.execute_sync(
            functools.partial(idaapi.register_action, action), ida_kernwin.MFF_FAST)
        ida_kernwin.execute_sync(
            functools.partial(idaapi.attach_action_to_menu,
                              self.toggle_parallel_menu_path,
                              self.toggle_parallel_action_name,
                              idaapi.SETMENU_APP),
            ida_kernwin.MFF_FAST,
        )

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
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.comment_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.rename_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.c_code_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(form, popup, GepettoPlugin.python_code_action_name, "Gepetto/")


# -----------------------------------------------------------------------------

class _ShowStatusPanelHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        try:
            STATUS.ensure_shown()
            STATUS.set_model(str(gepetto.config.model))
            STATUS.set_status("Idle", busy=False)
            STATUS.log("Status panel opened")
        except Exception as e:
            try:
                print(f"Failed to open status panel: {e}")
            except Exception:
                pass
        return 1

    def update(self, ctx):  # always enabled
        return idaapi.AST_ENABLE_ALWAYS


# -----------------------------------------------------------------------------

class ToggleParallelToolCallsHandler(idaapi.action_handler_t):
    def __init__(self, plugin: GepettoPlugin):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        try:
            current = self.plugin._parallel_toggle_state()
            new_val = "true" if not current else "false"
            gepetto.config.update_config("OpenAI", "PARALLEL_TOOL_CALLS", new_val)
            try:
                STATUS.ensure_shown()
                STATUS.set_status("Settings updated", busy=False)
                STATUS.log(f"Parallel tool calls: {'ON' if new_val == 'true' else 'OFF'}")
            except Exception:
                pass
            self.plugin.register_or_update_parallel_action()
        except Exception as e:
            try:
                print(f"Failed to toggle parallel tool calls: {e}")
            except Exception:
                pass
        return 1

    def update(self, ctx):  # always enabled
        return idaapi.AST_ENABLE_ALWAYS
