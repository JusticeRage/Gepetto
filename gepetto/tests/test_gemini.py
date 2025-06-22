import unittest
from unittest.mock import patch, MagicMock

# Ensure gepetto is in path for sibling imports, or adjust as per your project structure
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from gepetto.models.gemini import (
    Gemini,
    GEMINI_2_0_FLASH_MODEL_NAME, GEMINI_2_5_PRO_MODEL_NAME,
    GEMINI_2_5_FLASH_MODEL_NAME, GEMINI_2_5_FLASH_LITE_PREVIEW_MODEL_NAME
)
import gepetto.config

class TestGeminiModel(unittest.TestCase):

    def setUp(self):
        # Mock configuration for all tests
        self.mock_config_patcher = patch('gepetto.config.get_config')
        self.mock_get_config = self.mock_config_patcher.start()
        # Default mock behavior: API key is present
        self.mock_get_config.side_effect = lambda section, option, env_var=None, default=None: "test_api_key" if option == "API_KEY" else default

        # Mock the google.genai configure and GenerativeModel
        self.mock_google_configure_patcher = patch('gepetto.models.gemini.genai.configure')
        self.mock_google_configure = self.mock_google_configure_patcher.start()

        self.mock_generative_model_patcher = patch('gepetto.models.gemini.genai.GenerativeModel')
        self.mock_generative_model_constructor = self.mock_generative_model_patcher.start()

        # Mock instance for the GenerativeModel
        self.mock_model_instance = MagicMock()
        self.mock_generative_model_constructor.return_value = self.mock_model_instance

        # Mock ida_kernwin for execute_sync
        self.mock_ida_kernwin_patcher = patch('gepetto.models.gemini.ida_kernwin')
        self.mock_ida_kernwin = self.mock_ida_kernwin_patcher.start()
        # Make execute_sync run the callback immediately for testing
        self.mock_ida_kernwin.execute_sync.side_effect = lambda func, _: func()
        self.mock_ida_kernwin.MFF_WRITE = 0 # Placeholder value

    def tearDown(self):
        self.mock_config_patcher.stop()
        self.mock_google_configure_patcher.stop()
        self.mock_generative_model_patcher.stop()
        self.mock_ida_kernwin_patcher.stop()

    def test_supported_models(self):
        expected_models = [
            GEMINI_2_0_FLASH_MODEL_NAME, GEMINI_2_5_PRO_MODEL_NAME,
            GEMINI_2_5_FLASH_MODEL_NAME, GEMINI_2_5_FLASH_LITE_PREVIEW_MODEL_NAME
        ]
        self.assertEqual(Gemini.supported_models(), expected_models)

    def test_get_menu_name(self):
        self.assertEqual(Gemini.get_menu_name(), "Google Gemini")

    def test_is_configured_properly_true(self):
        self.assertTrue(Gemini.is_configured_properly())

    def test_is_configured_properly_false(self):
        self.mock_get_config.side_effect = lambda section, option, env_var=None, default=None: None if option == "API_KEY" else default
        self.assertFalse(Gemini.is_configured_properly())

    # This test is now covered by test_init_success_all_models
    # def test_init_success(self):
    #     gemini_model = Gemini(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model
    #     self.assertEqual(gemini_model.model_name, GEMINI_2_0_FLASH_MODEL_NAME)
    #     self.mock_google_configure.assert_called_with(api_key="test_api_key")

    def test_init_success_all_models(self):
        model_names = Gemini.supported_models()
        for model_name in model_names:
            with self.subTest(model=model_name):
                # Reset mock for configure if it's meant to be called once per init
                self.mock_google_configure.reset_mock()
                gemini_model = Gemini(model_name)
                self.assertEqual(gemini_model.model_name, model_name)
                self.mock_google_configure.assert_called_once_with(api_key="test_api_key")

    def test_init_no_api_key(self):
        self.mock_get_config.side_effect = lambda section, option, env_var=None, default=None: None if option == "API_KEY" else default
        with self.assertRaisesRegex(ValueError, "Please edit the configuration file to insert your Google Gemini API key!"):
            Gemini(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model

    def test_query_model_non_stream(self):
        gemini_model = Gemini(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model

        # Mock the response from client.generate_content
        mock_response = MagicMock()
        mock_response.candidates = [MagicMock()]
        mock_response.candidates[0].content.parts = [MagicMock()]
        mock_response.candidates[0].content.parts[0].text = "Test response"
        self.mock_model_instance.generate_content.return_value = mock_response

        callback_mock = MagicMock()
        query = "Test query"

        gemini_model.query_model(query, callback_mock, stream=False)

        self.mock_generative_model_constructor.assert_called_with(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model
        self.mock_model_instance.generate_content.assert_called_once()
        args, kwargs = self.mock_model_instance.generate_content.call_args
        self.assertEqual(args[0], [{"role": "user", "parts": [{"text": query}]}]) # messages
        self.assertFalse(kwargs['stream'])
        callback_mock.assert_called_once_with(response="Test response")

    def test_query_model_stream(self):
        gemini_model = Gemini(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model

        # Mock the streaming response
        mock_chunk1 = MagicMock()
        mock_chunk1.text = "Hello "
        mock_chunk1.candidates = [MagicMock()] # Simulate presence of candidates for stream logic
        mock_chunk2 = MagicMock()
        mock_chunk2.text = "World!"
        mock_chunk2.candidates = [MagicMock()]
        mock_chunk_empty = MagicMock() # Simulate end of stream signal
        mock_chunk_empty.text = ""
        mock_chunk_empty.candidates = [] # No candidates might mean end

        self.mock_model_instance.generate_content.return_value = [mock_chunk1, mock_chunk2, mock_chunk_empty]

        callback_mock = MagicMock()
        query = "Streaming query"

        gemini_model.query_model(query, callback_mock, stream=True)

        self.mock_generative_model_constructor.assert_called_with(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model
        self.mock_model_instance.generate_content.assert_called_once()
        args, kwargs = self.mock_model_instance.generate_content.call_args
        self.assertTrue(kwargs['stream'])

        # Check callback calls
        self.assertEqual(callback_mock.call_count, 3)
        callback_mock.assert_any_call("Hello ", False)
        callback_mock.assert_any_call("World!", False)
        callback_mock.assert_any_call("", True) # Assuming last empty content signifies end

    def test_query_model_exception(self):
        # Use one of the valid models for this test
        gemini_model = Gemini(GEMINI_2_0_FLASH_MODEL_NAME) # Use an available model
        self.mock_model_instance.generate_content.side_effect = Exception("API Error")

        callback_mock = MagicMock()
        # Mock print to check error message (optional)
        with patch('builtins.print') as mock_print:
            gemini_model.query_model("Error query", callback_mock, stream=False)

        callback_mock.assert_not_called() # Assuming callback is not called on exception in current impl
        mock_print.assert_any_call("General exception encountered while running the query: API Error")


if __name__ == '__main__':
    unittest.main()
