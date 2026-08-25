"""
Cybersecurity Incident Response Simulation Platform
B.Tech Cybersecurity Academic Capstone Project
Backend: Flask + SQLite + Rule-Based Detection Engine
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import sqlite3
import json
from datetime import datetime
import os
import socket

from database import get_db_connection, init_db
from detector import analyze_logs, DETECTION_RULES

app = Flask(__name__)
app.secret_key = 'simulated-cybersecurity-soc-secret-key'

# Ensure database is initialized
if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'incident_response.db')):
    init_db(force_reseed=True)

# Helper function to get stats for dashboard & navigation badges
def get_soc_metrics():
    conn = get_db_connection()
    total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    suspicious_events = conn.execute("SELECT COUNT(*) FROM logs WHERE is_suspicious = 1").fetchone()[0]
    critical_alerts = conn.execute("SELECT COUNT(*) FROM anomalies WHERE severity = 'CRITICAL'").fetchone()[0]
    total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    active_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE incident_status != 'Resolved'").fetchone()[0]
    primary_incident = conn.execute("SELECT * FROM incidents WHERE id = 'INC-2026-001'").fetchone()
    conn.close()

    return {
        "total_logs": total_logs,
        "suspicious_events": suspicious_events,
        "critical_alerts": critical_alerts,
        "total_iocs": total_iocs,
        "active_incidents": active_incidents,
        "incident_status": primary_incident['incident_status'] if primary_incident else "Active",
        "incident_severity": primary_incident['severity'] if primary_incident else "CRITICAL"
    }

# ----------------- PAGE ROUTES -----------------

@app.route('/')
@app.route('/dashboard')
def dashboard():
    """Page 1: SOC Executive Dashboard with KPIs, Charts, and Live Alert Feed."""
    metrics = get_soc_metrics()
    conn = get_db_connection()

    recent_anomalies = conn.execute("SELECT * FROM anomalies ORDER BY id DESC LIMIT 5").fetchall()
    recent_logs = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 8").fetchall()
    primary_incident = conn.execute("SELECT * FROM incidents WHERE id = 'INC-2026-001'").fetchone()

    # Chart 1: Severity breakdown
    severity_counts = {
        'LOW': conn.execute("SELECT COUNT(*) FROM logs WHERE severity = 'LOW'").fetchone()[0],
        'MEDIUM': conn.execute("SELECT COUNT(*) FROM logs WHERE severity = 'MEDIUM'").fetchone()[0],
        'HIGH': conn.execute("SELECT COUNT(*) FROM logs WHERE severity = 'HIGH'").fetchone()[0],
        'CRITICAL': conn.execute("SELECT COUNT(*) FROM logs WHERE severity = 'CRITICAL'").fetchone()[0],
    }

    # Chart 2: Failed vs Successful Logins
    auth_stats = {
        'successful': conn.execute("SELECT COUNT(*) FROM logs WHERE event_id = 4624").fetchone()[0],
        'failed': conn.execute("SELECT COUNT(*) FROM logs WHERE event_id = 4625").fetchone()[0],
        'other_events': conn.execute("SELECT COUNT(*) FROM logs WHERE event_id NOT IN (4624, 4625)").fetchone()[0]
    }

    conn.close()

    return render_template(
        'dashboard.html',
        metrics=metrics,
        recent_anomalies=recent_anomalies,
        recent_logs=recent_logs,
        primary_incident=primary_incident,
        severity_counts=severity_counts,
        auth_stats=auth_stats,
        current_page='dashboard'
    )

@app.route('/logs')
def logs():
    """Page 2: Windows SIEM Log Explorer with dynamic search, filters, and JSON modal."""
    metrics = get_soc_metrics()
    severity_filter = request.args.get('severity', '')
    event_id_filter = request.args.get('event_id', '')
    ip_filter = request.args.get('ip', '')
    suspicious_only = request.args.get('suspicious', '')
    search_query = request.args.get('q', '').strip()

    conn = get_db_connection()
    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)

    if event_id_filter:
        query += " AND event_id = ?"
        params.append(int(event_id_filter))

    if ip_filter:
        query += " AND (source_ip = ? OR destination_ip = ?)"
        params.extend([ip_filter, ip_filter])

    if suspicious_only == '1':
        query += " AND is_suspicious = 1"

    if search_query:
        query += " AND (username LIKE ? OR action LIKE ? OR process LIKE ? OR command_line LIKE ? OR source_ip LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term, term, term])

    query += " ORDER BY timestamp ASC"
    logs_data = conn.execute(query, params).fetchall()

    # Get distinct Event IDs and IPs for filter dropdowns
    event_ids = [row[0] for row in conn.execute("SELECT DISTINCT event_id FROM logs ORDER BY event_id").fetchall()]
    ip_list = [row[0] for row in conn.execute("SELECT DISTINCT source_ip FROM logs WHERE source_ip != '' ORDER BY source_ip").fetchall()]
    conn.close()

    return render_template(
        'logs.html',
        metrics=metrics,
        logs=logs_data,
        event_ids=event_ids,
        ip_list=ip_list,
        selected_severity=severity_filter,
        selected_event_id=event_id_filter,
        selected_ip=ip_filter,
        selected_suspicious=suspicious_only,
        search_query=search_query,
        current_page='logs'
    )

@app.route('/anomalies')
def anomalies():
    """Page 3 & 8: Rule-Based Anomaly Detection page with Viva explanation."""
    metrics = get_soc_metrics()
    conn = get_db_connection()
    anomalies_data = conn.execute("SELECT * FROM anomalies ORDER BY id ASC").fetchall()
    conn.close()

    return render_template(
        'anomalies.html',
        metrics=metrics,
        anomalies=anomalies_data,
        detection_rules=DETECTION_RULES,
        current_page='anomalies'
    )

@app.route('/iocs')
def iocs():
    """Page 4: Threat Intelligence & IOC Detection Matrix."""
    metrics = get_soc_metrics()
    conn = get_db_connection()
    iocs_data = conn.execute("SELECT * FROM iocs ORDER BY severity DESC, id ASC").fetchall()
    conn.close()

    # Group counts
    ioc_types = {}
    for ioc in iocs_data:
        t = ioc['ioc_type']
        ioc_types[t] = ioc_types.get(t, 0) + 1

    return render_template(
        'iocs.html',
        metrics=metrics,
        iocs=iocs_data,
        ioc_types=ioc_types,
        current_page='iocs'
    )

@app.route('/incidents')
def incidents():
    """Page 5: Incidents List Overview."""
    metrics = get_soc_metrics()
    conn = get_db_connection()
    incidents_list = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    conn.close()

    return render_template(
        'incidents.html',
        metrics=metrics,
        incidents=incidents_list,
        current_page='incidents'
    )

@app.route('/incident/<incident_id>')
def incident_detail(incident_id):
    """Page 5: Deep Incident Investigation Room."""
    metrics = get_soc_metrics()
    conn = get_db_connection()
    incident = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()

    if not incident:
        conn.close()
        return redirect(url_for('incidents'))

    # Correlated Logs
    correlated_logs = conn.execute(
        "SELECT * FROM logs WHERE is_suspicious = 1 ORDER BY timestamp ASC"
    ).fetchall()

    # Detected Anomalies
    anomalies_data = conn.execute("SELECT * FROM anomalies ORDER BY id ASC").fetchall()

    # Detected IOCs
    iocs_data = conn.execute("SELECT * FROM iocs ORDER BY id ASC").fetchall()

    # Investigation Notes
    notes = conn.execute(
        "SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY id DESC",
        (incident_id,)
    ).fetchall()

    # Containment actions summary
    actions = conn.execute(
        "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id ASC",
        (incident_id,)
    ).fetchall()

    conn.close()

    return render_template(
        'incident_detail.html',
        metrics=metrics,
        incident=incident,
        logs=correlated_logs,
        anomalies=anomalies_data,
        iocs=iocs_data,
        notes=notes,
        actions=actions,
        current_page='incidents'
    )

@app.route('/response')
def response_workflow():
    """Page 6: NIST/SANS 6-Phase Incident Response & Containment Console."""
    metrics = get_soc_metrics()
    conn = get_db_connection()
    primary_incident = conn.execute("SELECT * FROM incidents WHERE id = 'INC-2026-001'").fetchone()
    actions = conn.execute(
        "SELECT * FROM response_actions WHERE incident_id = 'INC-2026-001' ORDER BY id ASC"
    ).fetchall()
    conn.close()

    # Stats on containment
    total_actions = len(actions)
    completed_actions = sum(1 for a in actions if a['status'] == 'Completed')
    in_progress_actions = sum(1 for a in actions if a['status'] == 'In Progress')
    pending_actions = sum(1 for a in actions if a['status'] == 'Pending')

    progress_percent = int((completed_actions / total_actions * 100)) if total_actions > 0 else 0

    return render_template(
        'response.html',
        metrics=metrics,
        incident=primary_incident,
        actions=actions,
        total_actions=total_actions,
        completed_actions=completed_actions,
        in_progress_actions=in_progress_actions,
        pending_actions=pending_actions,
        progress_percent=progress_percent,
        current_page='response'
    )

@app.route('/report/<incident_id>')
def report(incident_id):
    """Page 7: Comprehensive Incident Report generator with Print/PDF export."""
    metrics = get_soc_metrics()
    conn = get_db_connection()
    incident = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()

    if not incident:
        conn.close()
        return redirect(url_for('incidents'))

    logs_data = conn.execute("SELECT * FROM logs WHERE is_suspicious = 1 ORDER BY timestamp ASC").fetchall()
    anomalies_data = conn.execute("SELECT * FROM anomalies ORDER BY id ASC").fetchall()
    iocs_data = conn.execute("SELECT * FROM iocs ORDER BY id ASC").fetchall()
    actions_data = conn.execute("SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id ASC", (incident_id,)).fetchall()
    notes_data = conn.execute("SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY id ASC", (incident_id,)).fetchall()
    conn.close()

    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        'report.html',
        metrics=metrics,
        incident=incident,
        logs=logs_data,
        anomalies=anomalies_data,
        iocs=iocs_data,
        actions=actions_data,
        notes=notes_data,
        generated_date=generated_date,
        current_page='report'
    )

# ----------------- REST API ENDPOINTS -----------------

@app.route('/api/stats')
def api_stats():
    """API endpoint for live dashboard analytics data."""
    conn = get_db_connection()

    # Login timestamps and counts
    login_timeline_rows = conn.execute("""
        SELECT substr(timestamp, 12, 5) as time_slot,
               SUM(CASE WHEN event_id = 4624 THEN 1 ELSE 0 END) as successful,
               SUM(CASE WHEN event_id = 4625 THEN 1 ELSE 0 END) as failed
        FROM logs
        GROUP BY time_slot
        ORDER BY time_slot ASC
    """).fetchall()

    timeline_data = {
        "labels": [r['time_slot'] for r in login_timeline_rows],
        "successful": [r['successful'] for r in login_timeline_rows],
        "failed": [r['failed'] for r in login_timeline_rows]
    }

    # Severity distribution
    severity_rows = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM logs
        GROUP BY severity
    """).fetchall()
    severity_map = {r['severity']: r['count'] for r in severity_rows}

    # Attack stages count
    stage_rows = conn.execute("""
        SELECT anomaly_type, COUNT(*) as count
        FROM anomalies
        GROUP BY anomaly_type
    """).fetchall()

    conn.close()

    return jsonify({
        "timeline": timeline_data,
        "severity": severity_map,
        "anomalies_by_type": {r['anomaly_type']: r['count'] for r in stage_rows}
    })

@app.route('/api/response_actions/update', methods=['POST'])
def api_update_action():
    """Update status of a containment action (Pending, In Progress, Completed)."""
    data = request.get_json() or {}
    action_id = data.get('action_id')
    new_status = data.get('status')

    if not action_id or new_status not in ['Pending', 'In Progress', 'Completed']:
        return jsonify({'success': False, 'error': 'Invalid action parameters'}), 400

    conn = get_db_connection()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if new_status == 'Completed' else None

    conn.execute(
        "UPDATE response_actions SET status = ?, executed_at = COALESCE(?, executed_at) WHERE id = ?",
        (new_status, now_str, action_id)
    )

    # Check overall incident progress
    actions = conn.execute("SELECT status FROM response_actions WHERE incident_id = 'INC-2026-001'").fetchall()
    all_done = all(a['status'] == 'Completed' for a in actions)
    some_done = any(a['status'] in ['In Progress', 'Completed'] for a in actions)

    new_inc_status = "Resolved" if all_done else ("Containment in Progress" if some_done else "Under Investigation")
    conn.execute("UPDATE incidents SET containment_status = ?, incident_status = ? WHERE id = 'INC-2026-001'",
                 ("Completed" if all_done else "In Progress", new_inc_status))

    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'action_id': action_id,
        'new_status': new_status,
        'incident_status': new_inc_status,
        'timestamp': now_str
    })

@app.route('/api/response_actions/execute_simulation', methods=['POST'])
def api_execute_simulation():
    """Safely simulates executing a containment command in the SOC Console."""
    data = request.get_json() or {}
    action_id = data.get('action_id')

    conn = get_db_connection()
    action = conn.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()

    if not action:
        conn.close()
        return jsonify({'success': False, 'error': 'Action not found'}), 404

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    simulated_output = ""

    if "Isolate" in action['action_title']:
        simulated_output = (
            f"[{now_str}] [SOC-AGENT-ISOLATE] Connecting to endpoint agent WS-FIN-042 (192.168.10.105)...\n"
            f"[{now_str}] [SOC-AGENT-ISOLATE] Applying host quarantine policy: Blocking non-SOC RFC1918 traffic.\n"
            f"[{now_str}] [SUCCESS] Workstation WS-FIN-042 successfully isolated. Management channel preserved."
        )
    elif "Disable" in action['action_title']:
        simulated_output = (
            f"[{now_str}] [SOC-DIR-SYNC] Connecting to Simulated Active Directory Domain Controller...\n"
            f"[{now_str}] [SOC-DIR-SYNC] Executing: Set-ADUser -Identity 'jdoe' -Enabled $false\n"
            f"[{now_str}] [SOC-DIR-SYNC] Revoking active Kerberos TGT & NTLM tokens for user 'jdoe'.\n"
            f"[{now_str}] [SUCCESS] User account 'jdoe' is now DISABLED. All active sessions invalidated."
        )
    elif "Block" in action['action_title']:
        simulated_output = (
            f"[{now_str}] [SOC-FIREWALL] Pushing ACL rule to Core Firewall FW-INTERNAL-01...\n"
            f"[{now_str}] [SOC-FIREWALL] Rule: access-list SOC_QUARANTINE deny ip host 192.168.10.45 any\n"
            f"[{now_str}] [SUCCESS] Rule committed. Source IP 192.168.10.45 dropped across all VLANs."
        )
    elif "Terminate" in action['action_title']:
        simulated_output = (
            f"[{now_str}] [SOC-EDR] Sending process kill signal to WS-FIN-042 for PID 4892 (powershell.exe)...\n"
            f"[{now_str}] [SOC-EDR] Terminating child process tree: cmd.exe (PID 4893), whoami.exe (PID 4894).\n"
            f"[{now_str}] [SUCCESS] Malicious process tree terminated. Volatile memory artifacts recorded."
        )
    else:
        simulated_output = (
            f"[{now_str}] [SOC-AUTOMATION] Executing response procedure for: {action['action_title']}...\n"
            f"[{now_str}] [SUCCESS] Action verified and completed safely."
        )

    conn.execute(
        "UPDATE response_actions SET status = 'Completed', executed_at = ?, result_log = ? WHERE id = ?",
        (now_str, simulated_output, action_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'action_id': action_id,
        'result_log': simulated_output,
        'timestamp': now_str
    })

@app.route('/api/incident/<incident_id>/notes', methods=['POST'])
def api_add_note(incident_id):
    """Add a timestamped analyst investigation note."""
    data = request.get_json() or {}
    author = data.get('author', 'SOC Analyst Alok')
    note_text = data.get('note_text', '').strip()
    note_type = data.get('note_type', 'Observation')

    if not note_text:
        return jsonify({'success': False, 'error': 'Note text cannot be empty'}), 400

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO investigation_notes (incident_id, author, timestamp, note_text, note_type) VALUES (?, ?, ?, ?, ?)",
        (incident_id, author, now_str, note_text, note_type)
    )
    note_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'note': {
            'id': note_id,
            'author': author,
            'timestamp': now_str,
            'note_text': note_text,
            'note_type': note_type
        }
    })

@app.route('/api/incident/<incident_id>/status', methods=['POST'])
def api_update_incident_status(incident_id):
    """Update overall incident status."""
    data = request.get_json() or {}
    new_status = data.get('status')

    valid_statuses = ['Under Investigation', 'Containment in Progress', 'Contained', 'Eradication in Progress', 'Resolved', 'Closed']
    if new_status not in valid_statuses:
        return jsonify({'success': False, 'error': 'Invalid status'}), 400

    conn = get_db_connection()
    conn.execute("UPDATE incidents SET incident_status = ? WHERE id = ?", (new_status, incident_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'new_status': new_status})

@app.route('/api/reset_simulation', methods=['POST'])
def api_reset_simulation():
    """Reset the database simulation to default fresh state for repeated viva demos."""
    init_db(force_reseed=True)
    return jsonify({'success': True, 'message': 'Simulation environment successfully reset to baseline.'})

def find_available_port(preferred_port=5050):
    """Find an available port starting with preferred_port, avoiding macOS AirPlay collision on 5000."""
    candidates = [preferred_port, 5000, 8080, 8000, 5001, 5055]
    for p in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', p))
                return p
            except OSError:
                continue
    return 5050

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 0)) or find_available_port(5050)
    print("\n" + "="*70)
    print(" 🛡️  CYBERSECURITY INCIDENT RESPONSE SIMULATION (SOC PLATFORM)")
    print("="*70)
    print(f" -> Access Dashboard at: http://127.0.0.1:{port}/")
    print(f" -> Port Selected: {port} (macOS AirPlay collision protected)")
    print(" -> Press Ctrl+C in this terminal to stop the server.")
    print("="*70 + "\n")
    app.run(host='0.0.0.0', port=port, debug=True)
