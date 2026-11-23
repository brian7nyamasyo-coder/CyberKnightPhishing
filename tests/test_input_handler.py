
import unittest
from unittest.mock import patch

from core.input_handler import (
    get_required_input,
    get_multiline_input
)


class TestInputHandler(unittest.TestCase):

    def test_required_input_rejects_empty_value(self):

        with patch(
            "builtins.input",
            side_effect=["", "   ", "security@example.com"]
        ):
            result = get_required_input("Email: ")

        self.assertEqual(result, "security@example.com")

    def test_multiline_input_collects_lines(self):

        with patch(
            "builtins.input",
            side_effect=[
                "Hello there",
                "Please verify your account",
                "END"
            ]
        ):
            result = get_multiline_input("Email content")

        self.assertEqual(
            result,
            "Hello there\nPlease verify your account"
        )

    def test_multiline_input_accepts_empty_content(self):

        with patch(
            "builtins.input",
            side_effect=["END"]
        ):
            result = get_multiline_input("Email content")

        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
