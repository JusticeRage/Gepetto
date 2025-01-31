import functools,threading
import ida_kernwin
from sider_ai_api import Session,MODELS,ADVANCED_MODELS
import gepetto.config
import gepetto.models.model_manager
from gepetto.models.base import LanguageModel

class Sider(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Sider"

    @staticmethod
    def supported_models():
        return MODELS+ADVANCED_MODELS

    def __init__(self, model):
        self.model = model
        token = gepetto.config.get_config("Sider", "TOKEN")
        context_id = gepetto.config.get_config("Sider", "CONTEXT_ID") or ""
        cookie = gepetto.config.get_config("Sider", "COOKIE")
        if token is None:
            raise ValueError("A Sider token is required")
        self.client = Session(token,context_id,cookie)

    def __str__(self):
        return "Sider (%s)"%self.model

    def query_model(self, query, cb, additional_model_options=None):
        """
        Function which sends a query to a GPT-API-compatible model and calls a callback when the response is available.
        Blocks until the whole response is received (though sider_ai_api uses a **generator** to support partial responses) 
        :param query: The request to send to the model that should be a **string**. But for compability, it can also be a dictionary.
        :param cb: The function to which the response will be passed to.
        :param additional_model_options: Additional parameters used when creating the model object (not used there) .
        """
        if additional_model_options is None:
            additional_model_options = {}
        try:
            if isinstance(query,dict):
                query=query[-1]["content"] # For compability with styles of OpenAI API, but Sider uses conversation ID in self.client.context_id

            response = self.client.chat(query,self.model)
            ida_kernwin.execute_sync(functools.partial(cb, response="".join(response)),
                                     ida_kernwin.MFF_WRITE)
        except Exception as err:
            print(_("{type} encountered while running the query: {error}").format(
                type=type(err).__name__,error=str(err)))

    # -----------------------------------------------------------------------------

    def query_model_async(self, query, cb, additional_model_options=None):
        """
        Function which sends a query to {model} and calls a callback when the response is available.
        The usage of parameters is same as the query_model method.
        """
        t = threading.Thread(target=self.query_model, args=[query, cb, additional_model_options])
        t.start()

gepetto.models.model_manager.register_model(Sider)
