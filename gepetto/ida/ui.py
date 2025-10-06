import functools
import os
import random
import string
import threading

import idaapi
import ida_hexrays
import ida_kernwin

import gepetto.config
from gepetto.ida.handlers import (
    ExplainHandler,
    ExplainWithContextHandler,
    GenerateCCodeHandler,
    GeneratePythonCodeHandler,
    RenameHandler,
    SwapModelHandler,
)
from gepetto.ida.comment_handler import CommentHandler
from gepetto.ida.cli import register_cli
from gepetto.ida.status_panel import get_status_panel
import gepetto.models.model_manager

_ = gepetto.config._


def _safe_execute_sync(callback):
    try:
        ida_kernwin.execute_sync(callback, ida_kernwin.MFF_FAST)
    except Exception:
        pass


# =============================================================================
# Setup the menus, hotkeys and cli in IDA
# =============================================================================

class GepettoPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "gepetto:explain_function"
    explain_menu_path = "Edit/Gepetto/" + _("Explain function")
    explain_with_context_action_name = "gepetto:explain_function_with_context"
    explain_with_context_menu_path = "Edit/Gepetto/" + _("Explain function with context")
    comment_action_name = "gepetto:comment_function"
    comment_menu_path = "Edit/Gepetto/" + _("Comment function")
    rename_action_name = "gepetto:rename_function"
    rename_menu_path = "Edit/Gepetto/" + _("Auto-rename")
    c_code_action_name = "gepetto:generate_c_code"
    c_code_menu_path = "Edit/Gepetto/" + _("Generate C Code")
    python_code_action_name = "gepetto:generate_python_code"
    python_code_menu_path = "Edit/Gepetto/" + _("Generate Python Code")
    auto_show_action_name = "gepetto:toggle_status_panel_auto_show"
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

        # Function explaining with context action
        explain_with_context_action = idaapi.action_desc_t(self.explain_with_context_action_name,
                                              _('Explain function with context'),
                                              ExplainWithContextHandler(),
                                              "Ctrl+Alt+Shift+G",
                                              _('Use {model} to explain the currently selected function with additional context').format(
                                                  model=str(gepetto.config.model)),
                                              452)
        idaapi.register_action(explain_with_context_action)

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
        idaapi.attach_action_to_menu(self.explain_with_context_menu_path, self.explain_with_context_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.comment_menu_path, self.comment_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.c_code_menu_path, self.c_code_action_name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.python_code_menu_path, self.python_code_action_name, idaapi.SETMENU_APP)

        self.generate_model_select_menu()

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        # Register CLI
        register_cli()

        options_menu = "Edit/Gepetto/" + _("Options")
        toggle_label = _("Auto-open status panel")
        self.auto_show_menu_path = f"{options_menu}/{toggle_label}"
        self._register_auto_show_action()
        if gepetto.config.auto_show_status_panel_enabled():
            ida_kernwin.execute_sync(lambda: get_status_panel().ensure_shown(), ida_kernwin.MFF_FAST)

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
                                      208 if str(gepetto.config.model) == model_name else -1)  # Icon #208 == check mark.
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

    def _register_auto_show_action(self, force_state=None):
        if not hasattr(self, "auto_show_menu_path"):
            return
        _safe_execute_sync(
            functools.partial(
                idaapi.detach_action_from_menu,
                self.auto_show_menu_path,
                self.auto_show_action_name,
            )
        )
        _safe_execute_sync(
            functools.partial(idaapi.unregister_action, self.auto_show_action_name)
        )

        if force_state is None:
            enabled = gepetto.config.auto_show_status_panel_enabled()
        else:
            enabled = bool(force_state)
        icon = 208 if enabled else -1
        self._auto_show_handler = ToggleStatusPanelAutoShowHandler(self)
        action = idaapi.action_desc_t(
            self.auto_show_action_name,
            _("Auto-open status panel"),
            self._auto_show_handler,
            "",
            _("Automatically focus the Gepetto status panel when a request starts."),
            icon,
        )
        _safe_execute_sync(functools.partial(idaapi.register_action, action))
        _safe_execute_sync(
            functools.partial(
                idaapi.attach_action_to_menu,
                self.auto_show_menu_path,
                self.auto_show_action_name,
                idaapi.SETMENU_APP,
            )
        )
        _safe_execute_sync(
            functools.partial(
                ida_kernwin.update_action_icon,
                self.auto_show_action_name,
                icon,
            )
        )

    # -----------------------------------------------------------------------------

    def refresh_auto_show_action(self, force_state=None):
        self._register_auto_show_action(force_state=force_state)

    # -----------------------------------------------------------------------------
    def _unregister_auto_show_action(self):
        if not hasattr(self, "auto_show_menu_path"):
            return
        _safe_execute_sync(
            functools.partial(
                idaapi.detach_action_from_menu,
                self.auto_show_menu_path,
                self.auto_show_action_name,
            )
        )
        _safe_execute_sync(
            functools.partial(idaapi.unregister_action, self.auto_show_action_name)
        )

    # -----------------------------------------------------------------------------

    def run(self, arg):
        pass

    # -----------------------------------------------------------------------------

    def term(self):
        self.detach_actions()
        if self.menu:
            self.menu.unhook()
        self._unregister_auto_show_action()
        get_status_panel().close()
        return


# -----------------------------------------------------------------------------

class ToggleStatusPanelAutoShowHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "GepettoPlugin"):
        super().__init__()
        self._plugin = plugin

    def activate(self, ctx):
        current_state = gepetto.config.auto_show_status_panel_enabled()
        new_state = not current_state
        gepetto.config.set_auto_show_status_panel(new_state)
        if new_state:
            ida_kernwin.execute_sync(lambda: get_status_panel().ensure_shown(), ida_kernwin.MFF_FAST)
        self._plugin.refresh_auto_show_action(force_state=new_state)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, form, popup, ctx=None):
        """Accept both legacy and new signatures to avoid SWIG signature introspection issues."""
        return 0

    def finish_populating_widget_popup(self, form, popup, ctx=None):
        widget = form
        popup_handle = popup
        if ctx is not None and hasattr(ctx, "widget") and ctx.widget is not None:
            widget = ctx.widget
        if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup_handle, GepettoPlugin.explain_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(widget, popup_handle, GepettoPlugin.explain_with_context_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(widget, popup_handle, GepettoPlugin.comment_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(widget, popup_handle, GepettoPlugin.rename_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(widget, popup_handle, GepettoPlugin.c_code_action_name, "Gepetto/")
            idaapi.attach_action_to_popup(widget, popup_handle, GepettoPlugin.python_code_action_name, "Gepetto/")
