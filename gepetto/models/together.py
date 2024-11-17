import together

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.openai import GPT

MISTRAL_MODEL_NAME = "mistralai/Mixtral-8x22B-Instruct-v0.1"

class Together(GPT):
    @staticmethod
    def get_menu_name() -> str:
        return "Together"

    @staticmethod
    def supported_models():
        return [MISTRAL_MODEL_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        # The plugin is configured properly if the API key is provided, otherwise it should not be shown.
        return bool(gepetto.config.get_config("Together", "API_KEY", "TOGETHER_API_KEY"))

    def __init__(self, model):
        try:
            super().__init__(model)
        except ValueError:
            pass  # May throw if the OpenAI API key isn't given, but we don't need any to use Together.

        self.model = model
        api_key = gepetto.config.get_config("Together", "API_KEY", "TOGETHER_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="Together"))

        base_url = gepetto.config.get_config("Together", "BASE_URL", "TOGETHER_BASE_URL")

        self.client = together.Together(
            api_key=api_key,
            base_url=base_url)

gepetto.models.model_manager.register_model(Together)
