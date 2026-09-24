#!/usr/bin/env python3

"""
AttackGuard Enterprise SIEM - SOAR Agent

Capabilities:
- TCP SYN scan correlation
- UDP scan correlation
- SSH brute-force correlation across SSH connections
- Automatic IP blocking
- Authenticated SIEM telemetry
- Sudo monitoring
- SSH authentication monitoring
- Kernel/iptables scan monitoring

Architecture:

    Attacker Kali
          |
          v
    Target Kali
       agent.py
          |
          v
    Windows SIEM
"""


import os
import sys
import time
import socket
import re
import requests
import subprocess
import threading

from collections import defaultdict, deque


# ============================================================
# CONFIGURATION
# ============================================================

# Windows SIEM collector
#
# Configure these values through environment variables instead of
# hard-coding lab-specific addresses or authentication tokens.
#
# Required:
#   ATTACKGUARD_TOKEN
#
# Optional:
#   ATTACKGUARD_SIEM_URL
#
# Example:
#   export ATTACKGUARD_SIEM_URL="http://<SIEM-IP>:5000/ingest"
#   export ATTACKGUARD_TOKEN="<your-token>"
#
# Never commit real credentials to source control.

SIEM_COLLECTOR_URL = os.getenv(
    "ATTACKGUARD_SIEM_URL",
    "http://127.0.0.1:5000/ingest"
)

ATTACKGUARD_TOKEN = os.getenv(
    "ATTACKGUARD_TOKEN",
    ""
)

HOSTNAME = socket.gethostname()


# ============================================================
# LOCAL IP
# ============================================================

def get_local_ip():

    try:

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        s.connect(
            ("8.8.8.8", 80)
        )

        ip = s.getsockname()[0]

        s.close()

        return ip

    except Exception:

        return "127.0.0.1"


LOCAL_IP = get_local_ip()


# ============================================================
# ACTIVE DEFENSE STATE
# ============================================================

blocked_ips = set()

blocked_ips_lock = threading.Lock()


# ============================================================
# DETECTION CORRELATION
# ============================================================

# TCP SYN scan tracking
scan_tracker = {}

# UDP scan tracking
udp_tracker = defaultdict(deque)

# SSH failed-login tracking
#
# Tracker is keyed by attacker IP.
#
# This allows SSH failures across multiple SSH
# connections to be correlated together.

ssh_failure_tracker = defaultdict(deque)


# Locks
scan_tracker_lock = threading.Lock()

udp_tracker_lock = threading.Lock()

ssh_failure_lock = threading.Lock()


# ============================================================
# DETECTION THRESHOLDS
# ============================================================

# ------------------------------------------------------------
# TCP SYN scan
# ------------------------------------------------------------

SCAN_WINDOW = 10
SCAN_THRESHOLD = 8


# ------------------------------------------------------------
# UDP scan
# ------------------------------------------------------------

UDP_SCAN_WINDOW = 10
UDP_SCAN_THRESHOLD = 8


# ------------------------------------------------------------
# SSH brute force
# ------------------------------------------------------------

SSH_WINDOW = 60
SSH_THRESHOLD = 5


# ============================================================
# TELEMETRY
# ============================================================

def _dispatch_http_worker(payload):

    """
    Send telemetry to Windows SIEM asynchronously.

    Authentication:
        X-AttackGuard-Token
    """

    headers = {
        "X-AttackGuard-Token": ATTACKGUARD_TOKEN,
        "Content-Type": "application/json"
    }

    try:

        response = requests.post(
            SIEM_COLLECTOR_URL,
            json=payload,
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:

            target = (
                payload
                .get("metadata", {})
                .get("scanned_target", "Unknown")
            )

            print(
                f"[TELEMETRY DELIVERED] "
                f"Status: 200 | "
                f"Target: {target}"
            )

        elif response.status_code == 401:

            print(
                "[TELEMETRY AUTH ERROR] "
                "Windows SIEM rejected the "
                "AttackGuard token."
            )

        else:

            print(
                f"[TELEMETRY WARNING] "
                f"SIEM returned HTTP "
                f"{response.status_code}"
            )

    except Exception as e:

        print(
            "[TELEMETRY NOTICE] "
            f"Backend delivery pending/error: {e}"
        )


def ship_telemetry_payload(
    raw_string,
    event_level,
    source_ip=None,
    target_subsystem="Local System"
):

    """
    Build and asynchronously send a normalized
    telemetry event to the Windows SIEM.
    """

    resolved_source_ip = (
        source_ip
        if source_ip
        else LOCAL_IP
    )

    payload = {

        "raw_message": raw_string,

        "event_type": event_level,

        "source_ip": resolved_source_ip,

        "source_host": HOSTNAME,

        "target_ip": LOCAL_IP,

        "metadata": {

            "ip": LOCAL_IP,

            "scanned_target": target_subsystem

        }

    }

    threading.Thread(
        target=_dispatch_http_worker,
        args=(payload,),
        daemon=True
    ).start()


# ============================================================
# ACTIVE RESPONSE
# ============================================================

def block_attacker_ip(
    attacker_ip,
    reason="Suspicious Activity"
):

    """
    Block an attacker IP using iptables.

    Safety:
    - Never block localhost.
    - Never block the target's own IP.
    - Never add duplicate blocks.
    - Only mark the IP blocked after iptables
      successfully installs the DROP rule.
    """

    if not attacker_ip:

        return False


    # --------------------------------------------------------
    # Safety protection
    # --------------------------------------------------------

    if attacker_ip in [
        "127.0.0.1",
        LOCAL_IP
    ]:

        print(
            "[DEFENSE SAFETY] "
            f"Refusing to block local IP: "
            f"{attacker_ip}"
        )

        return False


    # --------------------------------------------------------
    # Check existing block state
    # --------------------------------------------------------

    with blocked_ips_lock:

        if attacker_ip in blocked_ips:

            return True


    # --------------------------------------------------------
    # Display response
    # --------------------------------------------------------

    print()

    print("=" * 65)

    print("[ACTIVE DEFENSE]")

    print(
        f"Reason     : {reason}"
    )

    print(
        f"Attacker IP: {attacker_ip}"
    )

    print("=" * 65)


    # --------------------------------------------------------
    # Install iptables DROP rule
    # --------------------------------------------------------

    try:

        subprocess.run(
            [
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-s",
                attacker_ip,
                "-j",
                "DROP"
            ],
            check=True
        )


        # ----------------------------------------------------
        # Mark blocked only after successful firewall change
        # ----------------------------------------------------

        with blocked_ips_lock:

            blocked_ips.add(
                attacker_ip
            )


        print(
            "[SOAR IPS] "
            "IPTables DROP rule active for "
            f"{attacker_ip}"
        )


        # ----------------------------------------------------
        # Send response telemetry
        # ----------------------------------------------------

        ship_telemetry_payload(

            (
                f"[SOAR ACTIVE DEFENSE] "
                f"{reason}. "
                f"Firewall automatically blocked "
                f"attacker IP {attacker_ip}."
            ),

            "CRITICAL",

            source_ip=attacker_ip,

            target_subsystem="IPTables Firewall"

        )

        return True


    except Exception as e:

        print(
            f"[FIREWALL ERROR] {e}"
        )

        return False


# ============================================================
# SENSOR 1
# SUDO / PRIVILEGE MONITORING
# ============================================================

def run_journalctl_sudo_sensor():

    print(
        "[*] Activating Systemd Journal Sensor "
        "(sudo / privilege monitoring)..."
    )

    try:

        process = subprocess.Popen(

            [
                "journalctl",
                "-f",
                "-n",
                "0",
                "-q",
                "_COMM=sudo"
            ],

            stdout=subprocess.PIPE,

            stderr=subprocess.PIPE,

            text=True,

            bufsize=1

        )


        for line in iter(
            process.stdout.readline,
            ""
        ):

            line_clean = line.strip()

            if (
                line_clean
                and "COMMAND=" in line_clean
            ):

                ship_telemetry_payload(

                    (
                        "[Local Sudo Command Executed] "
                        f"{line_clean}"
                    ),

                    "MEDIUM",

                    target_subsystem="Local Root Shell"

                )


    except Exception as e:

        print(
            f"[-] Sudo sensor error: {e}"
        )


# ============================================================
# SENSOR 2
# TCP SYN / PORT SCAN DETECTION
# ============================================================

def run_journalctl_kernel_scan_sensor():

    print(
        "[*] Activating Kernel Scan Sensor "
        "(TCP + UDP reconnaissance)..."
    )


    # ========================================================
    # TCP LOGGING RULE
    # ========================================================

    try:

        check = subprocess.run(

            [
                "iptables",
                "-C",
                "INPUT",
                "-p",
                "tcp",
                "--syn",
                "!",
                "--dport",
                "22",
                "-j",
                "LOG",
                "--log-prefix",
                "ATTACKGUARD_SCAN: "
            ],

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL

        )


        if check.returncode != 0:

            subprocess.run(

                [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--syn",
                    "!",
                    "--dport",
                    "22",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "ATTACKGUARD_SCAN: "
                ],

                check=True

            )

            print(
                "[+] IPTables TCP port-scan "
                "logging rule attached."
            )


    except Exception as e:

        print(
            f"[-] TCP IPTables log setup note: {e}"
        )


    # ========================================================
    # UDP LOGGING RULE
    # ========================================================

    try:

        check_udp = subprocess.run(

            [
                "iptables",
                "-C",
                "INPUT",
                "-p",
                "udp",
                "-j",
                "LOG",
                "--log-prefix",
                "ATTACKGUARD_UDP_SCAN: "
            ],

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL

        )


        if check_udp.returncode != 0:

            subprocess.run(

                [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    "udp",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "ATTACKGUARD_UDP_SCAN: "
                ],

                check=True

            )

            print(
                "[+] IPTables UDP reconnaissance "
                "logging rule attached."
            )


    except Exception as e:

        print(
            f"[-] UDP IPTables log setup note: {e}"
        )


    # ========================================================
    # MONITOR KERNEL LOGS
    # ========================================================

    try:

        process = subprocess.Popen(

            [
                "journalctl",
                "-k",
                "-f",
                "-n",
                "0",
                "-q"
            ],

            stdout=subprocess.PIPE,

            stderr=subprocess.PIPE,

            text=True,

            bufsize=1

        )


        for line in iter(
            process.stdout.readline,
            ""
        ):

            # =================================================
            # TCP SCAN
            # =================================================

            if "ATTACKGUARD_SCAN:" in line:

                process_tcp_scan_event(line)


            # =================================================
            # UDP SCAN
            # =================================================

            elif "ATTACKGUARD_UDP_SCAN:" in line:

                process_udp_scan_event(line)


    except Exception as e:

        print(
            f"[-] Kernel scan sensor error: {e}"
        )


# ============================================================
# TCP SCAN EVENT PROCESSOR
# ============================================================

def process_tcp_scan_event(line):

    match = re.search(

        r"SRC=([0-9]+\."
        r"[0-9]+\."
        r"[0-9]+\."
        r"[0-9]+)",

        line

    )


    if not match:

        return


    attacker_ip = match.group(1)


    # --------------------------------------------------------
    # Ignore already-contained attackers
    # --------------------------------------------------------

    with blocked_ips_lock:

        if attacker_ip in blocked_ips:

            return


    now = time.time()


    # --------------------------------------------------------
    # Thread-safe scan tracker
    # --------------------------------------------------------

    with scan_tracker_lock:

        if attacker_ip not in scan_tracker:

            scan_tracker[
                attacker_ip
            ] = []

        scan_tracker[
            attacker_ip
        ].append(now)

        scan_tracker[
            attacker_ip
        ] = [

            timestamp

            for timestamp
            in scan_tracker[
                attacker_ip
            ]

            if (
                now - timestamp
                <= SCAN_WINDOW
            )

        ]

        event_count = len(
            scan_tracker[
                attacker_ip
            ]
        )


    print(

        "[NETWORK ACTIVITY] "
        f"{attacker_ip} -> "
        f"{event_count} SYN events/"
        f"{SCAN_WINDOW}s"

    )


    # --------------------------------------------------------
    # TCP SCAN DETECTED
    # --------------------------------------------------------

    if (
        event_count
        >= SCAN_THRESHOLD
    ):

        print()

        print(

            "[SCAN DETECTED] "
            f"{attacker_ip} generated "
            f"{event_count} SYN events "
            f"within "
            f"{SCAN_WINDOW} seconds."

        )


        # ----------------------------------------------------
        # Send detection telemetry
        # ----------------------------------------------------

        ship_telemetry_payload(

            (
                "[TCP PORT SCAN DETECTED] "
                f"{event_count} SYN events "
                f"from {attacker_ip} "
                f"within {SCAN_WINDOW} seconds."
            ),

            "HIGH",

            source_ip=attacker_ip,

            target_subsystem=(
                "Network Scan Detection"
            )

        )


        # ----------------------------------------------------
        # Active containment
        # ----------------------------------------------------

        block_attacker_ip(

            attacker_ip,

            reason=(

                "TCP Port Scan detected "
                f"({event_count} SYN events/"
                f"{SCAN_WINDOW}s)"

            )

        )


        # ----------------------------------------------------
        # Reset tracker
        # ----------------------------------------------------

        with scan_tracker_lock:

            scan_tracker.pop(
                attacker_ip,
                None
            )


# ============================================================
# UDP SCAN EVENT PROCESSOR
# ============================================================

def process_udp_scan_event(line):

    """
    Correlate UDP packets from the same source IP.

    A UDP reconnaissance pattern is considered suspicious
    when the same attacker generates enough UDP events within
    the configured time window.
    """

    match = re.search(

        r"SRC=([0-9]+\."
        r"[0-9]+\."
        r"[0-9]+\."
        r"[0-9]+)",

        line

    )


    if not match:

        return


    attacker_ip = match.group(1)


    # --------------------------------------------------------
    # Ignore already-contained attackers
    # --------------------------------------------------------

    with blocked_ips_lock:

        if attacker_ip in blocked_ips:

            return


    # --------------------------------------------------------
    # Ignore local traffic
    # --------------------------------------------------------

    if attacker_ip in [
        "127.0.0.1",
        LOCAL_IP
    ]:

        return


    now = time.time()


    # --------------------------------------------------------
    # Thread-safe UDP tracker
    # --------------------------------------------------------

    with udp_tracker_lock:

        failures = udp_tracker[
            attacker_ip
        ]


        # Remove expired events

        while failures:

            oldest = failures[0]

            if (
                now - oldest
                <= UDP_SCAN_WINDOW
            ):

                break

            failures.popleft()


        # Add current UDP event

        failures.append(now)


        event_count = len(
            failures
        )


    print(

        "[UDP ACTIVITY] "
        f"{attacker_ip} -> "
        f"{event_count} UDP events/"
        f"{UDP_SCAN_WINDOW}s"

    )


    # --------------------------------------------------------
    # UDP SCAN DETECTED
    # --------------------------------------------------------

    if (
        event_count
        >= UDP_SCAN_THRESHOLD
    ):

        print()

        print(

            "[UDP SCAN DETECTED] "
            f"{attacker_ip} generated "
            f"{event_count} UDP events "
            f"within "
            f"{UDP_SCAN_WINDOW} seconds."

        )


        # ----------------------------------------------------
        # Send detection telemetry
        # ----------------------------------------------------

        ship_telemetry_payload(

            (
                "[UDP PORT SCAN DETECTED] "
                f"{event_count} UDP events "
                f"from {attacker_ip} "
                f"within {UDP_SCAN_WINDOW} seconds."
            ),

            "HIGH",

            source_ip=attacker_ip,

            target_subsystem=(
                "UDP Scan Detection"
            )

        )


        # ----------------------------------------------------
        # Active containment
        # ----------------------------------------------------

        block_success = block_attacker_ip(

            attacker_ip,

            reason=(

                "UDP Port Scan detected "
                f"({event_count} UDP events/"
                f"{UDP_SCAN_WINDOW}s)"

            )

        )


        # ----------------------------------------------------
        # Reset tracker after successful containment
        # ----------------------------------------------------

        if block_success:

            with udp_tracker_lock:

                udp_tracker.pop(
                    attacker_ip,
                    None
                )


# ============================================================
# SSH FAILURE TRACKING
# ============================================================

def record_ssh_failure(attacker_ip):

    """
    Record one failed SSH authentication attempt.

    The counter is associated with the ATTACKER IP,
    not the SSH connection.
    """

    now = time.time()


    with ssh_failure_lock:

        failures = ssh_failure_tracker[
            attacker_ip
        ]


        # ----------------------------------------------------
        # Remove failures older than detection window
        # ----------------------------------------------------

        while failures:

            oldest = failures[0]

            if (
                now - oldest
                <= SSH_WINDOW
            ):

                break

            failures.popleft()


        # ----------------------------------------------------
        # Add current failed attempt
        # ----------------------------------------------------

        failures.append(now)


        # ----------------------------------------------------
        # Return correlated count
        # ----------------------------------------------------

        return len(
            failures
        )


def reset_ssh_failure_tracker(attacker_ip):

    """
    Remove attacker's SSH failure history after
    successful containment.
    """

    with ssh_failure_lock:

        ssh_failure_tracker.pop(
            attacker_ip,
            None
        )


# ============================================================
# SENSOR 3
# SSH AUTHENTICATION MONITORING
# ============================================================

def run_auth_log_sensor():

    auth_log = "/var/log/auth.log"


    print(

        "[*] Activating SSH Auth Sensor on: "
        f"{auth_log}"

    )


    if not os.path.exists(auth_log):

        print(

            "[-] SSH auth log not found: "
            f"{auth_log}"

        )

        return


    try:

        with open(

            auth_log,
            "r",
            errors="ignore"

        ) as log_file:


            # Start from end of existing log

            log_file.seek(0, 2)


            while True:

                line = log_file.readline()


                if not line:

                    time.sleep(0.3)

                    continue


                line_clean = line.strip()


                # ------------------------------------------------
                # Extract remote IP
                # ------------------------------------------------

                ip_match = re.search(

                    r"from\s+"
                    r"([0-9]+\."
                    r"[0-9]+\."
                    r"[0-9]+\."
                    r"[0-9]+)",

                    line_clean

                )


                attacker_ip = (

                    ip_match.group(1)

                    if ip_match

                    else None

                )


                # ------------------------------------------------
                # Ignore already blocked attackers
                # ------------------------------------------------

                if attacker_ip:

                    with blocked_ips_lock:

                        if attacker_ip in blocked_ips:

                            continue


                # ------------------------------------------------
                # SUCCESSFUL SSH LOGIN
                # ------------------------------------------------

                if (

                    "Accepted password"
                    in line_clean

                    or

                    "Accepted publickey"
                    in line_clean

                ):

                    ship_telemetry_payload(

                        (
                            "[SSH Successful Authentication] "
                            f"{line_clean}"
                        ),

                        "MEDIUM",

                        source_ip=attacker_ip,

                        target_subsystem=(
                            "SSHd Daemon (Port 22)"
                        )

                    )


                    print(

                        "[SSH LOGIN] "
                        "Successful authentication "
                        f"from {attacker_ip}"

                    )


                # ------------------------------------------------
                # FAILED SSH LOGIN
                # ------------------------------------------------

                elif (

                    "password failed"
                    in line_clean

                    or

                    "Failed password"
                    in line_clean

                ):


                    # --------------------------------------------
                    # No source IP
                    # --------------------------------------------

                    if not attacker_ip:

                        ship_telemetry_payload(

                            (
                                "[SSH Authentication Failure] "
                                f"{line_clean}"
                            ),

                            "HIGH",

                            target_subsystem=(
                                "SSH Service"
                            )

                        )

                        continue


                    # --------------------------------------------
                    # Record failure by attacker IP
                    # --------------------------------------------

                    failure_count = record_ssh_failure(
                        attacker_ip
                    )


                    print(

                        "[SSH FAILURE] "
                        f"{attacker_ip} -> "
                        f"{failure_count}/"
                        f"{SSH_THRESHOLD} failures "
                        f"(window: {SSH_WINDOW}s)"

                    )


                    # --------------------------------------------
                    # SSH BRUTE FORCE DETECTED
                    # --------------------------------------------

                    if (

                        failure_count
                        >= SSH_THRESHOLD

                    ):

                        print()

                        print(

                            "[SSH BRUTE FORCE DETECTED] "
                            f"{attacker_ip} generated "
                            f"{failure_count} failed "
                            f"SSH attempts within "
                            f"{SSH_WINDOW} seconds."

                        )


                        # ----------------------------------------
                        # Critical detection telemetry
                        # ----------------------------------------

                        ship_telemetry_payload(

                            (
                                "[SSH BRUTE FORCE DETECTED] "
                                f"{failure_count} failed SSH "
                                f"attempts from {attacker_ip} "
                                f"within {SSH_WINDOW} seconds."
                            ),

                            "CRITICAL",

                            source_ip=attacker_ip,

                            target_subsystem=(
                                "SSH Brute Force Detection"
                            )

                        )


                        # ----------------------------------------
                        # Active containment
                        # ----------------------------------------

                        block_success = block_attacker_ip(

                            attacker_ip,

                            reason=(

                                "SSH brute force detected "
                                f"({failure_count} failures/"
                                f"{SSH_WINDOW}s)"

                            )

                        )


                        # ----------------------------------------
                        # Reset tracker after containment
                        # ----------------------------------------

                        if block_success:

                            reset_ssh_failure_tracker(
                                attacker_ip
                            )


                    else:

                        # ----------------------------------------
                        # Normal individual failure
                        # ----------------------------------------

                        ship_telemetry_payload(

                            (
                                "[SSH Authentication Failure] "
                                f"{line_clean}"
                            ),

                            "HIGH",

                            source_ip=attacker_ip,

                            target_subsystem=(
                                "SSH Service"
                            )

                        )


    except Exception as e:

        print(
            f"[-] Auth log sensor error: {e}"
        )


# ============================================================
# FIREWALL RULE CLEANUP
# ============================================================

def cleanup_logging_rules():

    """
    Remove AttackGuard's own logging rules during
    graceful shutdown.
    """

    # --------------------------------------------------------
    # TCP rule
    # --------------------------------------------------------

    try:

        subprocess.run(

            [
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--syn",
                "!",
                "--dport",
                "22",
                "-j",
                "LOG",
                "--log-prefix",
                "ATTACKGUARD_SCAN: "
            ],

            stderr=subprocess.DEVNULL

        )

    except Exception:
        pass


    # --------------------------------------------------------
    # UDP rule
    # --------------------------------------------------------

    try:

        subprocess.run(

            [
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "udp",
                "-j",
                "LOG",
                "--log-prefix",
                "ATTACKGUARD_UDP_SCAN: "
            ],

            stderr=subprocess.DEVNULL

        )

    except Exception:
        pass


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 70)

    print(
        "        ATTACKGUARD SOAR AGENT"
    )

    print("=" * 70)


    print(
        f"Host     : {HOSTNAME}"
    )

    print(
        f"Local IP : {LOCAL_IP}"
    )

    print(
        f"SIEM     : {SIEM_COLLECTOR_URL}"
    )

    print(
        f"TCP Scan : {SCAN_THRESHOLD} SYNs/"
        f"{SCAN_WINDOW}s"
    )

    print(
        f"UDP Scan : {UDP_SCAN_THRESHOLD} events/"
        f"{UDP_SCAN_WINDOW}s"
    )

    print(
        f"SSH      : {SSH_THRESHOLD} failures/"
        f"{SSH_WINDOW}s"
    )

    print("=" * 70)


    # --------------------------------------------------------
    # Environment configuration checks
    # --------------------------------------------------------

    if not os.getenv("ATTACKGUARD_SIEM_URL"):
        print(
            "[i] Using default SIEM URL: "
            f"{SIEM_COLLECTOR_URL}"
        )

    # --------------------------------------------------------
    # Token configuration check
    # --------------------------------------------------------

    if (

        not ATTACKGUARD_TOKEN

        or

        ATTACKGUARD_TOKEN
        == "PASTE_THE_SAME_ATTACKGUARD_TOKEN_HERE"

    ):

        print(
            "[!] WARNING: AttackGuard token is not configured."
        )

        print(
            "[!] Set the ATTACKGUARD_TOKEN environment variable."
        )

        print(
            "[!] It must match the token configured "
            "for the Windows SIEM collector."
        )

        print(
            "[!] Example: export ATTACKGUARD_TOKEN="
            ""<your-token>""
        )

    else:

        print(
            "[+] SIEM authentication token configured."
        )


    # --------------------------------------------------------
    # Start sensors
    # --------------------------------------------------------

    threading.Thread(

        target=run_journalctl_sudo_sensor,

        daemon=True

    ).start()


    threading.Thread(

        target=run_journalctl_kernel_scan_sensor,

        daemon=True

    ).start()


    threading.Thread(

        target=run_auth_log_sensor,

        daemon=True

    ).start()


    # --------------------------------------------------------
    # Keep agent alive
    # --------------------------------------------------------

    try:

        while True:

            time.sleep(1)


    except KeyboardInterrupt:

        print()

        print(
            "[!] Disarming AttackGuard Agent..."
        )


        cleanup_logging_rules()


        print(
            "[+] AttackGuard agent stopped."
        )


        sys.exit(0)
