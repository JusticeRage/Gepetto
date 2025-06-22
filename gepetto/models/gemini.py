import functools
import re
import threading
import os

import httpx as _httpx
import ida_kernwin
from google.generativeai import GenerativeModel, configure # Assuming google-generativeai library
from google.generativeai.types import HarmCategory, HarmBlockThreshold # For content safety

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

GEMINI_1_5_FLASH_MODEL_NAME = "gemini-1.5-flash"
GEMINI_1_5_PRO_MODEL_NAME = "gemini-1.5-pro"
GEMINI_2_0_FLASH_MODEL_NAME = "gemini-2.0-flash"
GEMINI_2_5_PRO_MODEL_NAME = "gemini-2.5-pro"
GEMINI_2_5_FLASH_MODEL_NAME = "gemini-2.5-flash"
GEMINI_2_5_FLASH_LITE_PREVIEW_MODEL_NAME = "gemini-2.5-flash-lite-preview-06-17"


class Gemini(LanguageModel):
    @staticmethod
    def get_menu_name() -> str:
        return "Google Gemini"

    @staticmethod
    def supported_models():
        return [
            GEMINI_1_5_FLASH_MODEL_NAME,
            GEMINI_1_5_PRO_MODEL_NAME,
            GEMINI_2_0_FLASH_MODEL_NAME,
            GEMINI_2_5_PRO_MODEL_NAME,
            GEMINI_2_5_FLASH_MODEL_NAME,
            GEMINI_2_5_FLASH_LITE_PREVIEW_MODEL_NAME,
        ]

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("Gemini", "API_KEY", "GEMINI_API_KEY"))

    def __init__(self, model_name):
        self.model_name = model_name
        api_key = gepetto.config.get_config("Gemini", "API_KEY", "GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                _("Please edit the configuration file to insert your {api_provider} API key!")
                .format(api_provider="Google Gemini")
            )

        # Configure the Google AI client
        configure(api_key=api_key)

        # For Gemini, the client (GenerativeModel) is typically instantiated per request or per model
        # We'll instantiate it in query_model for now, or you can pre-initialize if preferred
        # self.client = GenerativeModel(self.model_name) # Example, might vary

        # Proxies with google-generativeai might require custom httpx client setup,
        # which is more involved than with OpenAI's library.
        # For now, we'll assume direct connection or environment-variable based proxy (e.g. HTTPS_PROXY)
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        if proxy:
            print(_("Proxy configuration for Gemini via google-generativeai library might require manual setup of HTTPS_PROXY environment variable."))


    def __str__(self):
        return self.model_name

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        try:
            if isinstance(query, str):
                # For simple string queries, adapt to Gemini's expected format if necessary
                # Gemini typically uses a list of content objects.
                # This might need adjustment based on how `query` is structured.
                # Assuming query is a simple text prompt for now.
                messages = [{"role": "user", "parts": [{"text": query}]}]
            else: # Assuming query is already in Gemini's expected message format
                messages = query

            # Safety settings - adjust as needed
            safety_settings = {
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            }

            # Initialize the model here or use a pre-initialized one
            # For Gemini, model names are often like 'gemini-1.5-pro-latest'
            # Ensure self.model_name matches the API's expected format
            client = GenerativeModel(self.model_name)

            if stream:
                response_stream = client.generate_content(
                    messages,
                    stream=True,
                    safety_settings=safety_settings,
                    **additional_model_options
                )
                for chunk in response_stream:
                    # Assuming chunk.text gives the content. Adjust if the API is different.
                    content = chunk.text if hasattr(chunk, "text") else ""
                    # Determine 'finished' based on Gemini's stream completion indication
                    # This is a placeholder; actual implementation depends on the library's stream handling
                    finished = False # Update this based on actual stream completion
                    if not content and not chunk.candidates: # Example condition for end of stream
                        finished = True
                    cb(content, finished)
            else:
                response = client.generate_content(
                    messages,
                    stream=False,
                    safety_settings=safety_settings,
                    **additional_model_options
                )
                # Accessing response content - this might vary based on Gemini API structure
                # common way: response.text or response.candidates[0].content.parts[0].text
                response_text = ""
                if response.candidates and response.candidates[0].content.parts:
                    response_text = response.candidates[0].content.parts[0].text
                elif hasattr(response, 'text'): # Fallback if .text attribute exists
                    response_text = response.text

                ida_kernwin.execute_sync(
                    functools.partial(cb, response=response_text),
                    ida_kernwin.MFF_WRITE,
                )

        except Exception as e:
            # Specific error handling for Gemini API if available, e.g. google.api_core.exceptions
            # For now, using a general exception
            error_message = _("General exception encountered while running the query: {error}").format(error=str(e))
            print(error_message)
            # Optionally, pass error to callback if your cb handles it
            # ida_kernwin.execute_sync(functools.partial(cb, response=error_message, error=True), ida_kernwin.MFF_WRITE)


    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        t = threading.Thread(
            target=self.query_model, args=[query, cb, stream, additional_model_options]
        )
        t.start()

gepetto.models.model_manager.register_model(Gemini)
