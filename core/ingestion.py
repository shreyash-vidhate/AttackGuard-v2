import re
import requests
import threading

from core.database import save_incident, update_incident_ai
from modules.threat_intel import check_ip_reputation
from modules.ai_analyst import generate_ai_triage

# Centralized configuration
try:
    from config import (
        ATTACKGUARD_TOKEN,
        TELEGRAM_BOT_TOKEN,
        TELEGRAM_CHAT_ID,
    )
except ImportError:
    ATTACKGUARD_TOKEN = ""
    TELEGRAM_BOT_TOKEN = ""
    TELEGRAM_CHAT_ID = ""


# ==========================================
# ATTACKGUARD AUTHENTICATION
# ==========================================

def validate_attackguard_token(provided_token):
    """
    Validates the token supplied by the Kali agent.

    The actual Flask /ingest route should call this function
    using the value from the X-AttackGuard-Token HTTP header.
    """

    if not ATTACKGUARD_TOKEN:
        print("[AUTH ERROR] ATTACKGUARD_TOKEN is not configured.")
        return False

    if not provided_token:
        return False

    return provided_token == ATTACKGUARD_TOKEN


# ==========================================
# TELEGRAM CRITICAL ALERT
# ==========================================

def send_telegram_critical_alert(raw_message, source_ip, target_asset):
    """
    Dispatches real-time Telegram notification for
    CRITICAL security incidents.
    """

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(
            "[TELEGRAM NOTICE] Telegram configuration missing. "
            "Skipping alert."
        )
        return

    clean_raw = str(raw_message).replace("\n", " ")
    clean_target = str(target_asset)

    alert_text = (
        "🚨 [ATTACKGUARD SIEM CRITICAL ALERT] 🚨\n\n"
        "• SOC Severity: CRITICAL\n"
        f"• Attacker IP: {source_ip}\n"
        f"• Target Vector: {clean_target}\n"
        f"• Forensic Evidence: {clean_raw}"
    )

    url = (
        f"https://api.telegram.org/"
        f"bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    )

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": alert_text
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(
                "[TELEGRAM SUCCESS] "
                "Critical alert dispatched."
            )
        else:
            print(
                f"[TELEGRAM API ERROR] "
                f"Status {response.status_code}: {response.text}"
            )

    except Exception as exc:
        print(
            f"[TELEGRAM NETWORK ERROR] {exc}"
        )


# ==========================================
# ASYNCHRONOUS AI ENRICHMENT
# ==========================================

def _async_enrichment_worker(
    log_id,
    raw_message,
    event_type,
    source_ip,
    target_asset
):
    """
    Executes AI triage and Telegram dispatch
    in a background thread.
    """

    try:
        # Generate Gemini/SOC analyst triage
        ai_summary = generate_ai_triage(
            raw_message,
            event_type,
            source_ip
        )

        # Update database with AI analysis
        update_incident_ai(
            log_id,
            ai_summary
        )

    except Exception as exc:
        print(
            f"[AI TRIAGE ERROR] {exc}"
        )

    # Telegram notification for critical events
    if str(event_type).upper() == "CRITICAL":
        send_telegram_critical_alert(
            raw_message,
            source_ip,
            target_asset
        )


# ==========================================
# INCOMING TELEMETRY PROCESSOR
# ==========================================

def process_incoming_log(
    data,
    client_remote_addr="127.0.0.1"
):
    """
    Processes telemetry received from the Kali
    AttackGuard agent.

    Authentication is intentionally handled by the
    Flask /ingest route in run.py before this function
    is called.
    """

    if not isinstance(data, dict):
        raise ValueError(
            "Incoming telemetry must be a JSON object."
        )

    raw_message = data.get(
        "raw_message",
        ""
    )

    event_type = data.get(
        "event_type",
        "INFORMATIONAL"
    )

    source_host = data.get(
        "source_host",
        "kali"
    )

    metadata = data.get(
        "metadata",
        {}
    )

    if not isinstance(metadata, dict):
        metadata = {}

    target_host_ip = metadata.get(
        "ip",
        client_remote_addr
    )

    # ==========================================
    # 1. RESOLVE SOURCE / ATTACKER IP
    # ==========================================

    source_ip = data.get(
        "source_ip"
    )

    # If source_ip is missing, local, or identical
    # to the target host, attempt to extract the
    # attacker IP from the raw event.
    if (
        not source_ip
        or source_ip in [
            "0.0.0.0",
            "127.0.0.1",
            target_host_ip
        ]
    ):

        # Example:
        # Failed password for root from 192.168.x.x
        ip_match = re.search(
            r"from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
            raw_message
        )

        if ip_match:
            source_ip = ip_match.group(1)

        else:
            # Generic IPv4 extraction
            ip_match_alt = re.search(
                r"(\d{1,3}\."
                r"\d{1,3}\."
                r"\d{1,3}\."
                r"\d{1,3})",
                raw_message
            )

            if ip_match_alt:
                source_ip = ip_match_alt.group(1)
            else:
                source_ip = client_remote_addr

    # ==========================================
    # 2. TARGET SUBSYSTEM / ATTACK VECTOR
    # ==========================================

    subsystem = metadata.get(
        "scanned_target"
    ) or "Local System"

    target_asset = (
        f"{source_host} "
        f"({target_host_ip}) "
        f"➔ [{subsystem}]"
    )

    # ==========================================
    # 3. THREAT INTELLIGENCE
    # ==========================================

    if (
        "SOAR" in raw_message
        or "dropped" in raw_message.lower()
        or "blocked" in raw_message.lower()
    ):
        threat_intel = (
            "RISK: HIGH "
            "(BLOCKED BY SOAR)"
        )

    else:
        try:
            threat_intel = check_ip_reputation(
                source_ip
            )
        except Exception as exc:
            print(
                f"[THREAT INTEL ERROR] {exc}"
            )

            threat_intel = (
                "Threat intelligence unavailable"
            )

    # ==========================================
    # 4. SAVE INCIDENT TO DATABASE
    # ==========================================

    initial_ai = (
        "Active SOAR defense invoked: "
        "Network containment applied."
        if "SOAR" in raw_message
        else
        "Analyzing telemetry..."
    )

    log_id = save_incident(
        raw_message=raw_message,
        event_type=event_type,
        source_ip=source_ip,
        threat_intel=threat_intel,
        target_asset=target_asset,
        ai_triage=initial_ai
    )

    # ==========================================
    # 5. BACKGROUND AI + TELEGRAM PROCESSING
    # ==========================================

    threading.Thread(
        target=_async_enrichment_worker,
        args=(
            log_id,
            raw_message,
            event_type,
            source_ip,
            target_asset
        ),
        daemon=True
    ).start()

    return log_id


# ==========================================
# BACKWARD COMPATIBILITY
# ==========================================

parse_incoming_telemetry = process_incoming_log