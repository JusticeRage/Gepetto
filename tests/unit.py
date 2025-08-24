import unittest

from gepetto.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_config(self):
        config = load_config()
        self.assertEqual(config.get('Gepetto', 'MODEL'), "gpt-4")


if __name__ == "__main__":
    unittest.main()
