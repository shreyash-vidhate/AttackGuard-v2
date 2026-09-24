from flask import Flask, request, jsonify, render_template, Response
import csv
import io

from core.database import (
    init_database_layer,
    save_incident,
    update_incident_ai,
    clear_all_records,
    get_metrics_and_logs,
    get_all_records_for_export,
    get_recent_logs,
    get_metrics,
    clear_logs,
    insert_log,
    get_recent_incidents,
    get_incident,
    close_incident,

    # Analytics
    get_all_analytics,
    get_analytics_overview,
    get_event_timeline,
    get_severity_distribution,
    get_attack_type_distribution,
    get_incident_status_distribution
)

from core.ingestion import (
    process_incoming_log,
    parse_incoming_telemetry,
    validate_attackguard_token
)

from modules.ai_analyst import (
    generate_ai_triage,
    run_gemini_analysis
)

from modules.threat_intel import (
    check_ip_reputation,
    run_threat_intel_enrichment
)


app = Flask(__name__)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

init_database_layer()


# =========================================================
# TELEMETRY INGESTION
# =========================================================

@app.route('/ingest', methods=['POST'])
@app.route('/api/ingest', methods=['POST'])
def ingest_log():

    # -----------------------------------------------------
    # AUTHENTICATE KALI AGENT
    # -----------------------------------------------------

    provided_token = request.headers.get(
        'X-AttackGuard-Token',
        ''
    )

    if not validate_attackguard_token(
        provided_token
    ):

        client_ip = request.remote_addr

        print(
            f"[AUTH BLOCK] Unauthorized telemetry "
            f"attempt from: {client_ip}"
        )

        return jsonify({
            "status": "error",
            "message": "Unauthorized"
        }), 401

    # -----------------------------------------------------
    # PROCESS TELEMETRY
    # -----------------------------------------------------

    try:

        data = request.get_json(
            force=True
        ) or {}

        client_ip = request.remote_addr

        process_incoming_log(
            data,
            client_ip
        )

        print(
            f"[+] Authenticated telemetry received "
            f"from: {client_ip}"
        )

        return jsonify({
            "status": "success",
            "message": "Telemetry processed"
        }), 200

    except Exception as e:

        print(
            f"[SERVER ERROR] "
            f"Ingestion failed: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# DASHBOARD
# =========================================================

@app.route('/')
def dashboard():

    return render_template(
        'dashboard.html'
    )


# =========================================================
# LOG API
# =========================================================

@app.route('/api/logs', methods=['GET'])
def get_logs():

    try:

        limit = request.args.get(
            'limit',
            default=100,
            type=int
        )

        limit = max(
            1,
            min(
                limit,
                1000
            )
        )

        result = get_metrics_and_logs(
            limit=limit
        )

        if not isinstance(
            result,
            dict
        ):

            raise TypeError(
                "get_metrics_and_logs() "
                "did not return a dictionary."
            )

        logs = result.get(
            "recent_logs",
            []
        )

        metrics = result.get(
            "metrics",
            {}
        )

        print(
            f"[DASHBOARD API] Logs: "
            f"{len(logs)} | Metrics: {metrics}"
        )

        return jsonify({
            "recent_logs": logs,
            "metrics": metrics,
            "status": "success"
        }), 200

    except Exception as e:

        print(
            f"[DASHBOARD API ERROR] "
            f"Failed to retrieve logs: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# INCIDENT API
# =========================================================

@app.route('/api/incidents', methods=['GET'])
def get_incidents():

    try:

        incidents = get_recent_incidents()

        return jsonify({
            "status": "success",
            "count": len(incidents),
            "incidents": incidents
        }), 200

    except Exception as e:

        print(
            f"[INCIDENT API ERROR] "
            f"Failed to retrieve incidents: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# SINGLE INCIDENT DETAILS
# =========================================================

@app.route(
    '/api/incidents/<int:incident_id>',
    methods=['GET']
)
def get_single_incident(
    incident_id
):

    try:

        incident = get_incident(
            incident_id
        )

        if incident is None:

            return jsonify({
                "status": "error",
                "message": "Incident not found"
            }), 404

        return jsonify({
            "status": "success",
            "incident": incident
        }), 200

    except Exception as e:

        print(
            f"[INCIDENT API ERROR] "
            f"Failed to retrieve incident "
            f"{incident_id}: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# CLOSE INCIDENT
# =========================================================

@app.route(
    '/api/incidents/<int:incident_id>/close',
    methods=['POST']
)
def close_single_incident(
    incident_id
):

    try:

        result = close_incident(
            incident_id
        )

        if result is False:

            return jsonify({
                "status": "error",
                "message": "Incident not found"
            }), 404

        return jsonify({
            "status": "success",
            "message": "Incident closed",
            "incident_id": incident_id
        }), 200

    except Exception as e:

        print(
            f"[INCIDENT API ERROR] "
            f"Failed to close incident "
            f"{incident_id}: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# =========================================================
# ANALYTICS API
# =========================================================
# =========================================================


# ---------------------------------------------------------
# FULL ANALYTICS
# ---------------------------------------------------------

@app.route(
    '/api/analytics',
    methods=['GET']
)
def analytics():

    try:

        minutes = request.args.get(
            'minutes',
            default=60,
            type=int
        )

        minutes = max(
            1,
            min(
                minutes,
                1440
            )
        )

        data = get_all_analytics(
            timeline_minutes=minutes
        )

        return jsonify({
            "status": "success",
            "data": data
        }), 200

    except Exception as e:

        print(
            f"[ANALYTICS ERROR] "
            f"Failed to generate analytics: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ---------------------------------------------------------
# ANALYTICS OVERVIEW
# ---------------------------------------------------------

@app.route(
    '/api/analytics/overview',
    methods=['GET']
)
def analytics_overview():

    try:

        data = get_analytics_overview()

        return jsonify({
            "status": "success",
            "data": data
        }), 200

    except Exception as e:

        print(
            f"[ANALYTICS ERROR] "
            f"Overview failed: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ---------------------------------------------------------
# EVENT TIMELINE
# ---------------------------------------------------------

@app.route(
    '/api/analytics/timeline',
    methods=['GET']
)
def analytics_timeline():

    try:

        minutes = request.args.get(
            'minutes',
            default=60,
            type=int
        )

        minutes = max(
            1,
            min(
                minutes,
                1440
            )
        )

        data = get_event_timeline(
            minutes
        )

        return jsonify({
            "status": "success",
            "minutes": minutes,
            "data": data
        }), 200

    except Exception as e:

        print(
            f"[ANALYTICS ERROR] "
            f"Timeline failed: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ---------------------------------------------------------
# SEVERITY DISTRIBUTION
# ---------------------------------------------------------

@app.route(
    '/api/analytics/severity',
    methods=['GET']
)
def analytics_severity():

    try:

        data = get_severity_distribution()

        return jsonify({
            "status": "success",
            "data": data
        }), 200

    except Exception as e:

        print(
            f"[ANALYTICS ERROR] "
            f"Severity failed: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ---------------------------------------------------------
# ATTACK TYPE DISTRIBUTION
# ---------------------------------------------------------

@app.route(
    '/api/analytics/attack-types',
    methods=['GET']
)
def analytics_attack_types():

    try:

        data = get_attack_type_distribution()

        return jsonify({
            "status": "success",
            "data": data
        }), 200

    except Exception as e:

        print(
            f"[ANALYTICS ERROR] "
            f"Attack type analysis failed: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ---------------------------------------------------------
# INCIDENT STATUS
# ---------------------------------------------------------

@app.route(
    '/api/analytics/incidents',
    methods=['GET']
)
def analytics_incidents():

    try:

        data = get_incident_status_distribution()

        return jsonify({
            "status": "success",
            "data": data
        }), 200

    except Exception as e:

        print(
            f"[ANALYTICS ERROR] "
            f"Incident analytics failed: {e}"
        )

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# =========================================================
# FORENSIC CSV EXPORT
# =========================================================

@app.route(
    '/api/export',
    methods=['GET']
)
def export_csv():

    records = get_all_records_for_export()

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow([
        'ID',
        'Timestamp',
        'Raw Message',
        'Event Type',
        'Source IP',
        'Threat Intel',
        'Target Asset',
        'AI Triage'
    ])

    for r in records:

        writer.writerow([
            r['id'],
            r['timestamp'],
            r['raw_message'],
            r['event_type'],
            r['source_ip'],
            r['threat_intel'],
            r['target_asset'],
            r['ai_triage']
        ])

    response = Response(
        output.getvalue(),
        mimetype='text/csv'
    )

    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; "
        "filename=attackguard_forensic_export.csv"
    )

    return response


# =========================================================
# CLEAR DATABASE
# =========================================================

@app.route(
    '/api/clear',
    methods=['POST']
)
def clear_db():

    clear_all_records()

    return jsonify({
        "status": "cleared"
    })


# =========================================================
# SERVER START
# =========================================================

if __name__ == '__main__':

    print(
        "AttackGuard SIEM Server Online "
        "-> Listening on http://0.0.0.0:5000"
    )

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )