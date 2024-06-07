import functools
import re
import threading

import httpx as _httpx
import ida_kernwin
import openai

from gepetto.models.base import LanguageModel
import gepetto.config


class GPT(LanguageModel):
    def __init__(self, model):
        self.model = model
        # Get API key
        api_key = gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY")
        if not api_key:
            print(_("Please edit the configuration file to insert your {api_provider} API key!")
                  .format(api_provider="OpenAI"))
            raise ValueError("No valid OpenAI API key found")

        proxy = gepetto.config.get_config("OpenAI", "OPENAI_PROXY")
        base_url = gepetto.config.get_config("OpenAI", "BASE_URL", "OPENAI_BASE_URL")

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxies=proxy,
            ) if proxy else None
        )

    def __str__(self):
        return self.model

    def query_model(self, query, cb, additional_model_options=None):
        """
        Function which sends a query to a GPT-API-compatible model and calls a callback when the response is available.
        Blocks until the response is received
        :param query: The request to send to the model
        :param cb: The function to which the response will be passed to.
        :param additional_model_options: Additional parameters used when creating the model object. Typically, for
        OpenAI, response_format={"type": "json_object"}.
        """
        if additional_model_options is None:
            additional_model_options = {}
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": query}
                ],
                **additional_model_options
            )
            ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].message.content),
                                     ida_kernwin.MFF_WRITE)
        except openai.BadRequestError as e:
            # Context length exceeded. Determine the max number of tokens we can ask for and retry.
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            if m:
                print(_("Unfortunately, this function is too big to be analyzed with the model's current API limits."))
            else:
                print(_("General exception encountered while running the query: {error}").format(error=str(e)))
        except openai.OpenAIError as e:
            print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
        except Exception as e:
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))

    # -----------------------------------------------------------------------------

    def query_model_async(self, query, cb, additional_model_options=None):
        """
        Function which sends a query to {model} and calls a callback when the response is available.
        :param query: The request to send to {model}
        :param cb: Tu function to which the response will be passed to.
        :param additional_model_options: Additional parameters used when creating the model object. Typically, for
        OpenAI, response_format={"type": "json_object"}.
        """
        if additional_model_options is None:
            additional_model_options = {}
        print(_("Request to {model} sent...").format(model=str(gepetto.config.model)))
        t = threading.Thread(target=self.query_model, args=[query, cb, additional_model_options])
        t.start()

