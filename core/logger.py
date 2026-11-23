
import logging
from logging.handlers import RotatingFileHandler

from config import (
    LOGS_DIR,
    LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_LEVEL
)


def setup_logger():
    """Configure CyberKnight application logging."""

    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("CyberKnight")

    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8"
    )

    file_handler.setLevel(
        getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    )

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


logger = setup_logger()
