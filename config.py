# AttackGuard v2 - Configuration Layer
#
# Secrets are loaded from environment variables.
# Never hard-code API keys, bot tokens, passwords, or authentication
# tokens in this file or commit them to GitHub.

import os


# ============================================================
# AUTHENTICATION
# ============================================================

ATTACKGUARD_TOKEN = os.getenv("ATTACKGUARD_TOKEN", "")


# ============================================================
# TELEGRAM ALERTING
# ============================================================

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


# ============================================================
# GEMINI AI
# ============================================================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


# ============================================================
# DATABASE
# ============================================================

DB_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "attackguard.db"
)


# ============================================================
# FLASK SERVER
# ============================================================

HOST = os.getenv("ATTACKGUARD_HOST", "0.0.0.0")

PORT = int(os.getenv("ATTACKGUARD_PORT", "5000"))

DEBUG = os.getenv("ATTACKGUARD_DEBUG", "false").lower() == "true"