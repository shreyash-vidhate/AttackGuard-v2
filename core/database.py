import sqlite3
import json
import re
from datetime import datetime, timedelta
from pathlib import Path


# =========================================================
# ATTACKGUARD DATABASE CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DB_DIR = BASE_DIR / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DB_DIR / "attackguard.db"

IST_FORMAT = "%d/%m/%Y %I:%M:%S %p"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    conn = sqlite3.connect(
        str(DB_PATH),
        timeout=10
    )

    conn.row_factory = sqlite3.Row

    return conn


# =========================================================
# TIMESTAMP HELPERS
# =========================================================

def _now_ist_string():
    return datetime.now().strftime(IST_FORMAT)


def _parse_ist_timestamp(value):
    """
    Convert AttackGuard IST timestamp string into datetime.

    Supported example:

        22/09/2026 04:38:45 PM
    """

    if not value:
        return None

    if isinstance(value, datetime):
        return value

    value = str(value).strip()

    formats = [
        IST_FORMAT,
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S"
    ]

    for fmt in formats:

        try:
            return datetime.strptime(
                value,
                fmt
            )

        except ValueError:
            continue

    return None


def _compact_timestamp(value):
    """
    Produce a compact timestamp for unique incident keys.
    """

    parsed = _parse_ist_timestamp(value)

    if parsed is None:

        parsed = datetime.now()

    return parsed.strftime(
        "%Y%m%d%H%M%S%f"
    )


# =========================================================
# TARGET ASSET NORMALIZATION
# =========================================================

def normalize_target_asset(target_asset):
    """
    Convert event-specific targets into the actual protected asset.

    Example:

        kali (192.168.198.129) → [Network Scan Detection]

    becomes:

        kali (192.168.198.129)

    This is important because different security sensors can
    describe the same target differently.
    """

    if not target_asset:

        return "unknown"

    target = str(
        target_asset
    ).strip()

    # Remove Unicode arrow and everything after it.
    target = re.split(
        r"\s*(?:→|->|=>)\s*",
        target,
        maxsplit=1
    )[0].strip()

    # Remove bracketed sensor labels if no arrow was present.
    target = re.sub(
        r"\s*\[[^\]]+\]\s*$",
        "",
        target
    ).strip()

    return target or "unknown"


# =========================================================
# EVENT CLASSIFICATION
# =========================================================

def classify_event(
    raw_message,
    event_type
):
    """
    Convert raw telemetry into a normalized SOC event category.
    """

    message = (
        str(raw_message or "")
        .lower()
    )

    event = (
        str(event_type or "")
        .upper()
    )

    # IMPORTANT:
    # Containment must be checked before reconnaissance.
    # Otherwise a message such as:
    #
    # "[SOAR ACTIVE DEFENSE] TCP Port Scan detected..."
    #
    # could incorrectly become Network Reconnaissance.

    containment_patterns = [
        "soar active defense",
        "automated containment",
        "firewall automatically blocked",
        "iptables firewall",
        "network containment",
        "attacker ip blocked",
        "firewall blocked"
    ]

    if any(
        pattern in message
        for pattern in containment_patterns
    ):

        return (
            "Automated Containment",
            None,
            "CRITICAL"
        )

    # -----------------------------------------------------
    # Network reconnaissance
    # -----------------------------------------------------

    reconnaissance_patterns = [
        "tcp port scan",
        "port scan detected",
        "network scan",
        "syn events",
        "nmap",
        "network reconnaissance",
        "service scanning"
    ]

    if (
        event == "HIGH"
        or any(
            pattern in message
            for pattern in reconnaissance_patterns
        )
    ):

        return (
            "Network Reconnaissance",
            {
                "id": "T1046",
                "name": "Network Service Scanning"
            },
            "HIGH"
        )

    # -----------------------------------------------------
    # SSH brute force
    # -----------------------------------------------------

    brute_force_patterns = [
        "failed password",
        "failed ssh",
        "ssh brute",
        "brute force",
        "invalid user",
        "authentication failure",
        "multiple ssh failures"
    ]

    if any(
        pattern in message
        for pattern in brute_force_patterns
    ):

        return (
            "SSH Brute Force",
            {
                "id": "T1110.001",
                "name": "Password Guessing"
            },
            "HIGH"
        )

    # -----------------------------------------------------
    # Successful authentication
    # -----------------------------------------------------

    successful_auth_patterns = [
        "accepted password",
        "accepted publickey",
        "successful login",
        "successful authentication",
        "login succeeded"
    ]

    if any(
        pattern in message
        for pattern in successful_auth_patterns
    ):

        return (
            "Successful Authentication",
            {
                "id": "T1078",
                "name": "Valid Accounts"
            },
            "MEDIUM"
        )

    # -----------------------------------------------------
    # Privilege escalation / sudo
    # -----------------------------------------------------

    sudo_patterns = [
        "sudo",
        "privilege escalation",
        "sudo command",
        "sudo activity"
    ]

    if any(
        pattern in message
        for pattern in sudo_patterns
    ):

        return (
            "Privilege Escalation",
            {
                "id": "T1548.003",
                "name": "Sudo and Sudo Caching"
            },
            "HIGH"
        )

    # -----------------------------------------------------
    # Medium
    # -----------------------------------------------------

    if event == "MEDIUM":

        return (
            "Security Anomaly",
            None,
            "MEDIUM"
        )

    # -----------------------------------------------------
    # Critical
    # -----------------------------------------------------

    if event == "CRITICAL":

        return (
            "Critical Security Event",
            None,
            "CRITICAL"
        )

    # -----------------------------------------------------
    # Informational
    # -----------------------------------------------------

    return (
        "System Activity",
        None,
        "INFO"
    )


# =========================================================
# SEVERITY HELPERS
# =========================================================

SEVERITY_RANK = {
    "INFO": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def _highest_severity(
    current,
    incoming
):

    current = (
        str(current or "INFO")
        .upper()
    )

    incoming = (
        str(incoming or "INFO")
        .upper()
    )

    if (
        SEVERITY_RANK.get(
            incoming,
            1
        )
        >
        SEVERITY_RANK.get(
            current,
            1
        )
    ):

        return incoming

    return current


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_database_layer():

    conn = get_connection()

    cursor = conn.cursor()

    # -----------------------------------------------------
    # LOG TABLE
    # -----------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            raw_message TEXT,

            event_type TEXT,

            source_ip TEXT,

            threat_intel TEXT,

            target_asset TEXT,

            ai_triage TEXT

        )
        """
    )

    # -----------------------------------------------------
    # INCIDENT TABLE
    # -----------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_key TEXT UNIQUE NOT NULL,

            source_ip TEXT,

            target_asset TEXT,

            first_seen TEXT,

            last_seen TEXT,

            severity TEXT,

            status TEXT DEFAULT 'OPEN',

            event_count INTEGER DEFAULT 0,

            attack_chain TEXT,

            mitre_techniques TEXT

        )
        """
    )

    # -----------------------------------------------------
    # PERFORMANCE INDEXES
    # -----------------------------------------------------

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_logs_timestamp
        ON logs(timestamp)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_logs_source_ip
        ON logs(source_ip)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_logs_event_type
        ON logs(event_type)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_incidents_source
        ON incidents(source_ip)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_incidents_status
        ON incidents(status)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_incidents_severity
        ON incidents(severity)
        """
    )

    conn.commit()

    conn.close()


# =========================================================
# INCIDENT CORRELATION
# =========================================================

def _find_correlated_incident(
    cursor,
    source_ip,
    target_asset,
    event_timestamp
):

    parsed_timestamp = _parse_ist_timestamp(
        event_timestamp
    )

    if parsed_timestamp is None:

        return None

    window_start = (
        parsed_timestamp -
        timedelta(minutes=10)
    )

    window_end = (
        parsed_timestamp +
        timedelta(minutes=10)
    )

    rows = cursor.execute(
        """
        SELECT *

        FROM incidents

        WHERE source_ip = ?

        AND target_asset = ?

        AND status = 'OPEN'

        ORDER BY id DESC
        """,
        (
            source_ip,
            target_asset
        )
    ).fetchall()

    for row in rows:

        first_seen = _parse_ist_timestamp(
            row["first_seen"]
        )

        last_seen = _parse_ist_timestamp(
            row["last_seen"]
        )

        if first_seen is None:

            continue

        comparison_time = (
            last_seen
            or first_seen
        )

        if (
            window_start
            <=
            comparison_time
            <=
            window_end
        ):

            return row

    return None


# =========================================================
# SAVE LOG + CORRELATE INCIDENT
# =========================================================

def save_incident(
    raw_message,
    event_type,
    source_ip,
    threat_intel,
    target_asset,
    ai_triage="Analyzing telemetry..."
):

    timestamp = _now_ist_string()

    normalized_target = normalize_target_asset(
        target_asset
    )

    (
        event_name,
        mitre,
        calculated_severity
    ) = classify_event(
        raw_message,
        event_type
    )

    conn = get_connection()

    cursor = conn.cursor()

    try:

        # -------------------------------------------------
        # 1. SAVE RAW TELEMETRY
        # -------------------------------------------------

        cursor.execute(
            """
            INSERT INTO logs (

                timestamp,
                raw_message,
                event_type,
                source_ip,
                threat_intel,
                target_asset,
                ai_triage

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                raw_message,
                event_type,
                source_ip,
                threat_intel,
                target_asset,
                ai_triage
            )
        )

        log_id = cursor.lastrowid

        # -------------------------------------------------
        # 2. FIND EXISTING OPEN INCIDENT
        # -------------------------------------------------

        incident = _find_correlated_incident(
            cursor,
            source_ip,
            normalized_target,
            timestamp
        )

        # -------------------------------------------------
        # 3. UPDATE EXISTING INCIDENT
        # -------------------------------------------------

        if incident:

            existing_chain = []

            existing_mitre = []

            try:

                existing_chain = json.loads(
                    incident["attack_chain"]
                    or "[]"
                )

            except Exception:

                existing_chain = []


            try:

                existing_mitre = json.loads(
                    incident["mitre_techniques"]
                    or "[]"
                )

            except Exception:

                existing_mitre = []


            new_chain_item = {
                "event": event_name,
                "log_id": log_id,
                "timestamp": timestamp
            }

            existing_chain.append(
                new_chain_item
            )


            # Prevent duplicate MITRE mappings.

            if mitre:

                already_exists = any(
                    item.get("id") == mitre["id"]
                    for item in existing_mitre
                )

                if not already_exists:

                    existing_mitre.append(
                        mitre
                    )


            updated_severity = _highest_severity(
                incident["severity"],
                calculated_severity
            )


            cursor.execute(
                """
                UPDATE incidents

                SET
                    last_seen = ?,
                    severity = ?,
                    event_count = ?,
                    attack_chain = ?,
                    mitre_techniques = ?

                WHERE id = ?
                """,
                (
                    timestamp,
                    updated_severity,
                    int(
                        incident["event_count"]
                        or 0
                    ) + 1,
                    json.dumps(
                        existing_chain
                    ),
                    json.dumps(
                        existing_mitre
                    ),
                    incident["id"]
                )
            )


            print(
                "[CORRELATION] Incident "
                f"#{incident['id']} UPDATED | "
                f"{source_ip} | "
                f"{normalized_target} | "
                f"Events: "
                f"{int(incident['event_count'] or 0) + 1} | "
                f"Severity: {updated_severity}"
            )


        # -------------------------------------------------
        # 4. CREATE NEW INCIDENT
        # -------------------------------------------------

        else:

            incident_key = (
                f"{source_ip}|"
                f"{normalized_target}|"
                f"{_compact_timestamp(timestamp)}|"
                f"{log_id}"
            )

            attack_chain = [
                {
                    "event": event_name,
                    "log_id": log_id,
                    "timestamp": timestamp
                }
            ]

            mitre_techniques = []

            if mitre:

                mitre_techniques.append(
                    mitre
                )


            cursor.execute(
                """
                INSERT INTO incidents (

                    incident_key,
                    source_ip,
                    target_asset,
                    first_seen,
                    last_seen,
                    severity,
                    status,
                    event_count,
                    attack_chain,
                    mitre_techniques

                )

                VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?)
                """,
                (
                    incident_key,
                    source_ip,
                    normalized_target,
                    timestamp,
                    timestamp,
                    calculated_severity,
                    1,
                    json.dumps(
                        attack_chain
                    ),
                    json.dumps(
                        mitre_techniques
                    )
                )
            )


            incident_id = cursor.lastrowid

            print(
                "[CORRELATION] New incident "
                f"#{incident_id} | "
                f"{source_ip} | "
                f"{normalized_target} | "
                f"{event_name}"
            )


        conn.commit()

        return log_id

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()


# =========================================================
# UPDATE AI TRIAGE
# =========================================================

def update_incident_ai(
    log_id,
    ai_triage
):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE logs

        SET ai_triage = ?

        WHERE id = ?
        """,
        (
            ai_triage,
            log_id
        )
    )

    conn.commit()

    conn.close()


# =========================================================
# RECENT LOGS
# =========================================================

def get_recent_logs(
    limit=100
):

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT *

        FROM logs

        ORDER BY id DESC

        LIMIT ?
        """,
        (
            int(limit),
        )
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# METRICS
# =========================================================

def get_metrics():

    conn = get_connection()

    cursor = conn.cursor()

    total = cursor.execute(
        "SELECT COUNT(*) FROM logs"
    ).fetchone()[0]

    critical = cursor.execute(
        """
        SELECT COUNT(*)
        FROM logs
        WHERE UPPER(event_type) = 'CRITICAL'
        """
    ).fetchone()[0]

    high = cursor.execute(
        """
        SELECT COUNT(*)
        FROM logs
        WHERE UPPER(event_type) = 'HIGH'
        """
    ).fetchone()[0]

    medium = cursor.execute(
        """
        SELECT COUNT(*)
        FROM logs
        WHERE UPPER(event_type) = 'MEDIUM'
        """
    ).fetchone()[0]

    info = cursor.execute(
        """
        SELECT COUNT(*)
        FROM logs
        WHERE UPPER(event_type) = 'INFO'
        """
    ).fetchone()[0]

    open_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) = 'OPEN'
        """
    ).fetchone()[0]

    closed_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) = 'CLOSED'
        """
    ).fetchone()[0]

    critical_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(severity) = 'CRITICAL'
        """
    ).fetchone()[0]

    conn.close()

    return {

        "total": total,

        "critical": critical,

        "high": high,

        "medium": medium,

        "info": info,

        "open_incidents":
            open_incidents,

        "closed_incidents":
            closed_incidents,

        "critical_incidents":
            critical_incidents

    }


# =========================================================
# COMBINED LOG API DATA
# =========================================================

class MetricsAndLogsResult(dict):
    """
    Compatibility wrapper.

    Behaves like a dictionary for the current run.py:

        result["recent_logs"]
        result["metrics"]

    Also supports the older code pattern:

        logs, metrics = get_metrics_and_logs()
    """

    def __iter__(self):
        yield self.get("recent_logs", [])
        yield self.get("metrics", {})


def get_metrics_and_logs(limit=100):

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 100

    # Safety limit
    limit = max(
        1,
        min(limit, 1000)
    )

    logs = get_recent_logs(
        limit
    )

    metrics = get_metrics()

    return MetricsAndLogsResult({
        "recent_logs": logs,
        "metrics": metrics,
        "status": "success"
    })
# =========================================================
# FORENSIC EXPORT
# =========================================================

def get_all_records_for_export():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT *

        FROM logs

        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# CLEAR DATABASE
# =========================================================

def clear_all_records():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM logs"
    )

    cursor.execute(
        "DELETE FROM incidents"
    )

    conn.commit()

    conn.close()

    print(
        "[DATABASE] Logs and incidents cleared."
    )


def clear_logs():

    clear_all_records()


# =========================================================
# INCIDENT RETRIEVAL
# =========================================================

def _decode_incident(row):

    incident = dict(row)

    try:

        incident["attack_chain"] = json.loads(
            incident.get(
                "attack_chain"
            )
            or "[]"
        )

    except Exception:

        incident["attack_chain"] = []


    try:

        incident["mitre_techniques"] = json.loads(
            incident.get(
                "mitre_techniques"
            )
            or "[]"
        )

    except Exception:

        incident["mitre_techniques"] = []


    return incident


def get_recent_incidents(
    limit=50
):

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT *

        FROM incidents

        ORDER BY id DESC

        LIMIT ?
        """,
        (
            int(limit),
        )
    ).fetchall()

    conn.close()

    return [
        _decode_incident(row)
        for row in rows
    ]


def get_incident(
    incident_id
):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT *

        FROM incidents

        WHERE id = ?
        """,
        (
            incident_id,
        )
    ).fetchone()

    conn.close()

    if row is None:

        return None

    return _decode_incident(
        row
    )


def close_incident(
    incident_id
):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE incidents

        SET status = 'CLOSED'

        WHERE id = ?
        """,
        (
            incident_id,
        )
    )

    changed = (
        cursor.rowcount > 0
    )

    conn.commit()

    conn.close()

    return changed


# =========================================================
# =========================================================
# ANALYTICS ENGINE
# =========================================================
# =========================================================


# =========================================================
# ANALYTICS OVERVIEW
# =========================================================

def get_analytics_overview():

    metrics = get_metrics()

    conn = get_connection()

    cursor = conn.cursor()

    total_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        """
    ).fetchone()[0]

    open_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) = 'OPEN'
        """
    ).fetchone()[0]

    closed_incidents = cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) = 'CLOSED'
        """
    ).fetchone()[0]

    conn.close()

    return {

        "logs": metrics["total"],

        "critical_logs":
            metrics["critical"],

        "high_logs":
            metrics["high"],

        "medium_logs":
            metrics["medium"],

        "info_logs":
            metrics["info"],

        "total_incidents":
            total_incidents,

        "open_incidents":
            open_incidents,

        "closed_incidents":
            closed_incidents,

        "critical_incidents":
            metrics["critical_incidents"]

    }


# =========================================================
# SEVERITY DISTRIBUTION
# =========================================================

def get_severity_distribution():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            UPPER(COALESCE(event_type, 'INFO'))
            AS severity,
            COUNT(*) AS count

        FROM logs

        GROUP BY
            UPPER(COALESCE(event_type, 'INFO'))
        """
    ).fetchall()

    conn.close()

    result = []

    # Fixed order makes dashboard rendering predictable.

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "INFO"
    ]

    values = {
        row["severity"]:
            row["count"]
        for row in rows
    }

    for severity in severity_order:

        result.append(
            {
                "severity": severity,
                "count": int(
                    values.get(
                        severity,
                        0
                    )
                )
            }
        )

    return result


# =========================================================
# ATTACK TYPE DISTRIBUTION
# =========================================================

def get_attack_type_distribution():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            raw_message,
            event_type

        FROM logs
        """
    ).fetchall()

    conn.close()

    counts = {}

    for row in rows:

        (
            event_name,
            _,
            _
        ) = classify_event(
            row["raw_message"],
            row["event_type"]
        )

        counts[event_name] = (
            counts.get(
                event_name,
                0
            ) + 1
        )


    result = [
        {
            "attack_type": name,
            "count": count
        }

        for name, count
        in counts.items()
    ]


    result.sort(
        key=lambda item:
            item["count"],
        reverse=True
    )

    return result


# =========================================================
# INCIDENT STATUS DISTRIBUTION
# =========================================================

def get_incident_status_distribution():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            UPPER(COALESCE(status, 'OPEN'))
            AS status,
            COUNT(*) AS count

        FROM incidents

        GROUP BY
            UPPER(COALESCE(status, 'OPEN'))
        """
    ).fetchall()

    conn.close()

    values = {
        row["status"]:
            row["count"]
        for row in rows
    }

    return [

        {
            "status": "OPEN",
            "count": int(
                values.get(
                    "OPEN",
                    0
                )
            )
        },

        {
            "status": "CLOSED",
            "count": int(
                values.get(
                    "CLOSED",
                    0
                )
            )
        }

    ]


# =========================================================
# EVENT TIMELINE
# =========================================================

def get_event_timeline(
    minutes=60
):

    try:

        minutes = int(
            minutes
        )

    except Exception:

        minutes = 60


    minutes = max(
        1,
        min(
            minutes,
            1440
        )
    )


    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            id,
            timestamp,
            event_type

        FROM logs

        ORDER BY id ASC
        """
    ).fetchall()

    conn.close()


    now = datetime.now()

    cutoff = (
        now -
        timedelta(
            minutes=minutes
        )
    )


    buckets = {}


    for row in rows:

        parsed = _parse_ist_timestamp(
            row["timestamp"]
        )

        if parsed is None:

            continue

        if parsed < cutoff:

            continue


        # Minute-level bucket.

        bucket_time = parsed.replace(
            second=0,
            microsecond=0
        )

        bucket_key = bucket_time.strftime(
            "%H:%M"
        )


        if bucket_key not in buckets:

            buckets[bucket_key] = {

                "time": bucket_key,

                "critical": 0,

                "high": 0,

                "medium": 0,

                "info": 0

            }


        severity = (
            str(
                row["event_type"]
                or "INFO"
            )
            .lower()
        )


        if severity == "critical":

            buckets[bucket_key][
                "critical"
            ] += 1

        elif severity == "high":

            buckets[bucket_key][
                "high"
            ] += 1

        elif severity == "medium":

            buckets[bucket_key][
                "medium"
            ] += 1

        else:

            buckets[bucket_key][
                "info"
            ] += 1


    # Return chronological order.

    result = list(
        buckets.values()
    )

    result.sort(
        key=lambda item:
            item["time"]
    )

    return result


# =========================================================
# FULL ANALYTICS PAYLOAD
# =========================================================

def get_all_analytics(
    timeline_minutes=60
):

    return {

        "overview":
            get_analytics_overview(),

        "timeline":
            get_event_timeline(
                timeline_minutes
            ),

        "severity":
            get_severity_distribution(),

        "attack_types":
            get_attack_type_distribution(),

        "incident_status":
            get_incident_status_distribution()

    }


# =========================================================
# BACKWARD COMPATIBILITY ALIASES
# =========================================================

insert_log = save_incident

init_db = init_database_layer