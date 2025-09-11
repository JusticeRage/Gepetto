import unittest


class ConfigTests(unittest.TestCase):
    def test_load_config(self):
        import sys
        from types import SimpleNamespace

        sys.modules.setdefault(
            "ida_kernwin",
            SimpleNamespace(execute_sync=lambda *a, **k: None, MFF_WRITE=0),
        )
        import gepetto.config as cfg

        cfg.load_config()
        self.assertEqual(cfg.parsed_ini.get("Gepetto", "MODEL"), "gpt-4o")


class GeminiSchemaTests(unittest.TestCase):
    def test_sanitize_schema_removes_default(self):
        import sys
        from types import SimpleNamespace

        sys.modules.setdefault(
            "ida_kernwin",
            SimpleNamespace(execute_sync=lambda *a, **k: None, MFF_WRITE=0),
        )
        from gepetto.models.gemini import _sanitize_schema

        schema = {
            "type": "object",
            "properties": {
                "x": {"type": "string", "default": "hi"}
            },
            "default": {},
        }

        cleaned = _sanitize_schema(schema)

        self.assertNotIn("default", cleaned)
        self.assertNotIn("default", cleaned["properties"]["x"])

    def test_sanitize_schema_filters_unknown_required(self):
        import sys
        from types import SimpleNamespace

        sys.modules.setdefault(
            "ida_kernwin",
            SimpleNamespace(execute_sync=lambda *a, **k: None, MFF_WRITE=0),
        )
        from gepetto.models.gemini import _sanitize_schema

        schema = {
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "required": ["a", "b"],
        }

        cleaned = _sanitize_schema(schema)

        self.assertEqual(cleaned["required"], ["a"])


class GeminiArgsTests(unittest.TestCase):
    def test_mapcomposite_args_to_dict(self):
        import sys
        from types import SimpleNamespace

        sys.modules.setdefault(
            "ida_kernwin",
            SimpleNamespace(execute_sync=lambda *a, **k: None, MFF_WRITE=0),
        )
        from gepetto.models.gemini import _to_serializable
        from google.genai.types import FunctionCall

        fc = FunctionCall(name="foo", args={"a": 1, "b": {"c": "d"}})

        self.assertEqual(_to_serializable(fc.args), {"a": 1, "b": {"c": "d"}})


if __name__ == "__main__":
    unittest.main()
