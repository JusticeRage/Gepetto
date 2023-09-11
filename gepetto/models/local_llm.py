import functools
import re
import threading
# import os

import ida_kernwin
import openai

from gepetto.models.base import LanguageModel
import gepetto.config

from gepetto.models.openai import GPT
_ = gepetto.config.translate.gettext


class CodeLLaMa(GPT):
    def __init__(self, model):
        # We don't need an API key for https://github.com/oobabooga/text-generation-webui/tree/main/extensions/openai
        OPENAI_API_KEY="sk-111111111111111111111111111111111111111111111111"
        openai.api_key = OPENAI_API_KEY
        # XXX DELETE WHEN IT WORKS ON ITS OWN     openai.api_base = gepetto.config.g   os.environ['OPENAI_API_BASE']           # "http://localhost:5001/v1"
        self.model = model

    def __str__(self):
        return self.model

    def query_model(self, query, cb, max_tokens=6500):
        """
        Function which sends a query to gpt-3.5-turbo or gpt-4 and calls a callback when the response is available.
        Blocks until the response is received
        :param query: The request to send to gpt-3.5-turbo or gpt-4
        :param cb: Tu function to which the response will be passed to.
        """
        try:
            response = openai.ChatCompletion.create(
                model="x",      # not needed, since it's already selected
                messages=[
                    {"role": "user", "content": query}
                ]
            )
            print(f'Got answer: {response.choices[0]["message"]["content"]}')
            ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0]["message"]["content"]),
                                     ida_kernwin.MFF_WRITE)
        except openai.InvalidRequestError as e:
            # XXX FIXME: for a local LLM, this error string might be different! Note sure if
            # we can rely on searching in the error message. Also: openai might change that error message
            # actually at any time ...
            #
            # Context length exceeded. Determine the max number of tokens we can ask for and retry.
            m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                          r'prompt;', str(e))
            if not m:
                print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
                return
            (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
            max_tokens = hard_limit - prompt_tokens
            if max_tokens >= 750:
                print(_("Context length exceeded! Reducing the completion tokens to "
                        "{max_tokens}...").format(max_tokens=max_tokens))
                self.query_model(query, cb, max_tokens)
            else:
                print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")

        except openai.OpenAIError as e:
            print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
        except Exception as e:
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))

    # -----------------------------------------------------------------------------

    def query_model_async(self, query, cb):
        """
        Function which sends a query to {model} and calls a callback when the response is available.
        :param query: The request to send to {model}
        :param cb: Tu function to which the response will be passed to.
        """
        print(_("Request to {model} sent...").format(model=str(gepetto.config.model)))
        t = threading.Thread(target=self.query_model, args=[query, cb])
        t.start()
