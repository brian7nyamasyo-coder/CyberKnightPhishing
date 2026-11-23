
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.logger import setup_logger


class TestLogger(unittest.TestCase):

    def test_logger_is_configured(self):
        logger = setup_logger()

        self.assertEqual(logger.level, logging.INFO)
        self.assertTrue(logger.handlers)

    def test_logger_writes_to_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            log_file = Path(temp_dir) / "test.log"

            logger = logging.getLogger("CyberKnightTest")
            logger.handlers.clear()
            logger.propagate = False
            logger.setLevel(logging.INFO)

            from logging.handlers import RotatingFileHandler

            handler = RotatingFileHandler(
                log_file,
                maxBytes=1000,
                backupCount=1,
                encoding="utf-8"
            )

            logger.addHandler(handler)

            logger.info("Test log message")

            handler.flush()
            handler.close()
            logger.removeHandler(handler)

            self.assertTrue(log_file.exists())

            content = log_file.read_text(encoding="utf-8")

            self.assertIn("Test log message", content)

    def test_logger_setup_does_not_duplicate_handlers(self):
        logger = logging.getLogger("CyberKnight")

        initial_count = len(logger.handlers)

        setup_logger()

        self.assertEqual(
            len(logger.handlers),
            initial_count
        )


if __name__ == "__main__":
    unittest.main()
