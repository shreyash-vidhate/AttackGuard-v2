import requests
import config


def send_telegram_notification(source_ip, target_asset, ai_summary):
    """
    Send a Telegram notification for a critical AttackGuard incident.

    Telegram credentials are loaded from config.py, which reads them
    from environment variables. No credentials are stored in source code.
    """

    bot_token = config.TELEGRAM_BOT_TOKEN
    chat_id = config.TELEGRAM_CHAT_ID

    # Telegram integration is optional.
    if not bot_token or not chat_id:
        print("[*] Telegram notification skipped: credentials not configured.")
        return

    message_payload = (
        "🚨 *[ATTACKGUARD CRISIS ALERT]* 🚨\n"
        "====================================\n"
        f"🌐 *Source Attacker IP:* `{source_ip}`\n"
        f"🖥️ *Target Attack Path:* `{target_asset}`\n\n"
        "🤖 *GEMINI AI THREAT TRIAGE SUMMARY:*\n"
        f"_{ai_summary}_\n"
        "===================================="
    )

    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": message_payload,
                "parse_mode": "Markdown",
            },
            timeout=5,
        )

    except Exception as e:
        print(f"[-] Telegram routing failure: {e}")