import functools
import re
import threading
import os

import httpx as _httpx
import ida_kernwin
import google.generativeai as genai
from google.generativeai import types

from gepetto.models.base import LanguageModel
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

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

        genai.configure(api_key=api_key)
        
        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        if proxy:
            print(_("Proxy configuration for Gemini via google-generativeai library might require manual setup of HTTPS_PROXY environment variable."))


    def __str__(self):
        return self.model_name

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        generation_config = {}
        # Translate the OpenAI-specific response_format to what Gemini expects
        if "response_format" in additional_model_options and additional_model_options["response_format"].get("type") == "json_object":
            generation_config["response_mime_type"] = "application/json"
            del additional_model_options["response_format"]


        try:
            if isinstance(query, str):
                messages = [{"role": "user", "parts": [{"text": query}]}]
            else:
                messages = query

            safety_settings = {
                types.HarmCategory.HARM_CATEGORY_HARASSMENT: types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                types.HarmCategory.HARM_CATEGORY_HATE_SPEECH: types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
                types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            }

            client = genai.GenerativeModel(self.model_name)

            if stream:
                response_stream = client.generate_content(
                    messages,
                    stream=True,
                    safety_settings=safety_settings,
                    generation_config=generation_config if generation_config else None,
                    **additional_model_options
                )
                for chunk in response_stream:
                    content = chunk.text if hasattr(chunk, "text") else ""
                    finished = False
                    if not content and not chunk.candidates:
                        finished = True
                    cb(content, finished)
            else:
                response = client.generate_content(
                    messages,
                    stream=False,
                    safety_settings=safety_settings,
                    generation_config=generation_config if generation_config else None,
                    **additional_model_options
                )
                response_text = ""
                if response.candidates and response.candidates[0].content.parts:
                    response_text = response.candidates[0].content.parts[0].text
                elif hasattr(response, 'text'):
                    response_text = response.text

                ida_kernwin.execute_sync(
                    functools.partial(cb, response=response_text),
                    ida_kernwin.MFF_WRITE,
                )

        except Exception as e:
            error_message = _("General exception encountered while running the query: {error}").format(error=str(e))
            print(error_message)


    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        t = threading.Thread(
            target=self.query_model, args=[query, cb, stream, additional_model_options]
        )
        t.start()

gepetto.models.model_manager.register_model(Gemini)