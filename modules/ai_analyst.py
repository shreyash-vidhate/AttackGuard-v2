import os
from google import genai


def generate_ai_triage(
    raw_message,
    event_type="INFORMATIONAL",
    source_ip="127.0.0.1"
):
    """
    Generates dynamic AI triage using the Google Gemini API.

    The Gemini API key must be supplied through the
    GEMINI_API_KEY environment variable.

    No API credentials are stored in source code.
    """

    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if api_key:
        try:
            client = genai.Client(api_key=api_key)

            prompt = (
                "You are a Senior SOC Analyst.\n"
                "Analyze this raw security log and write a concise, "
                "unique 1-sentence incident assessment summary:\n\n"
                f"Severity Level: {event_type}\n"
                f"Source IP: {source_ip}\n"
                f"Log Content: {raw_message}"
            )

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )

            if response.text:
                return response.text.strip()

        except Exception as e:
            print(f"[⚠️ GEMINI API NOTICE] Fallback due to: {e}")

    # Dynamic Fallback Matrix
    raw_lower = raw_message.lower()

    if (
        "soar" in raw_lower
        or "blocked" in raw_lower
        or "dropped" in raw_lower
    ):
        return (
            f"CRITICAL: SOAR IPS auto-dropped reconnaissance "
            f"traffic originating from {source_ip}."
        )

    if "accepted password" in raw_lower:
        return (
            f"CRITICAL: Remote SSH session established from {source_ip}."
        )

    if "sudo:" in raw_lower or "command=" in raw_lower:
        return (
            "MEDIUM: Administrative command executed on local "
            "shell by host user."
        )

    return f"Informational telemetry logged for host {source_ip}."


run_gemini_analysis = generate_ai_triage