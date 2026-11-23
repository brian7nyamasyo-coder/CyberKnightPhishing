
from pathlib import Path


# ==========================================
# APPLICATION SETTINGS
# ==========================================

APP_NAME = "CyberKnight Phishing Detector"
APP_VERSION = "1.0.0"


# ==========================================
# PROJECT DIRECTORIES
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

REPORTS_DIR = BASE_DIR / "reports" / "generated"
LOGS_DIR = BASE_DIR / "logs"


# ==========================================
# REPORT SETTINGS
# ==========================================

MAX_REPORTS = 10

REPORT_PREFIX = "cyberknight_report_"
HTML_REPORT_PREFIX = "cyberknight_html_report_"


# ==========================================
# LOGGING SETTINGS
# ==========================================

LOG_FILE = LOGS_DIR / "cyberknight.log"

LOG_MAX_BYTES = 1_000_000

LOG_BACKUP_COUNT = 3

LOG_LEVEL = "INFO"
