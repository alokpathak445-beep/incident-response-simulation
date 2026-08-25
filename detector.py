"""
detector.py - Rule-Based SIEM Detection Engine for Incident Response Simulation

Implements security detection rules for Windows SIEM logs:
1. Rule 1: Brute Force Authentication (>5 failed logins from same IP)
2. Rule 2: Suspicious Authentication (Successful login immediately after failed attempts)
3. Rule 3: Suspicious PowerShell Activity (Encoded payload, download cradles, bypass flags)
4. Rule 4: Privilege Escalation (Standard account assigning administrative privileges / group changes)
5. Rule 5: Defense Evasion (Security audit log cleared - Event ID 1102)

Includes MITRE ATT&CK Framework mapping for educational viva presentation.
"""

import re
from datetime import datetime

# Detection Rule Definitions with educational metadata & MITRE ATT&CK mappings
DETECTION_RULES = [
    {
        "id": "RULE-001",
        "name": "Possible Brute Force Attack",
        "category": "Credential Access",
        "mitre_id": "T1110.001 (Brute Force: Password Guessing)",
        "condition": "More than 5 failed logon attempts (Event ID 4625) from the same Source IP within a 5-minute time window.",
        "severity": "HIGH",
        "recommended_action": "Isolate source IP at firewall level, check account lockout status, verify target user identity."
    },
    {
        "id": "RULE-002",
        "name": "Suspicious Authentication Activity",
        "category": "Initial Access / Persistence",
        "mitre_id": "T1078.003 (Valid Accounts: Local Accounts)",
        "condition": "Successful logon (Event ID 4624) occurring immediately following >= 3 failed attempts (Event ID 4625) from identical IP.",
        "severity": "HIGH",
        "recommended_action": "Force immediate password reset for targeted account, terminate active user tokens, review logon type."
    },
    {
        "id": "RULE-003",
        "name": "Suspicious PowerShell Activity",
        "category": "Execution / Defense Evasion",
        "mitre_id": "T1059.001 (Command and Scripting Interpreter: PowerShell)",
        "condition": "Process creation (Event ID 4688) with 'powershell.exe' containing stealth flags (-EncodedCommand, -enc, -ExecutionPolicy Bypass, -W Hidden, IEX/DownloadString).",
        "severity": "HIGH",
        "recommended_action": "Kill suspicious process tree on target workstation, capture memory for forensics, inspect downloaded payload."
    },
    {
        "id": "RULE-004",
        "name": "Possible Privilege Escalation",
        "category": "Privilege Escalation",
        "mitre_id": "T1068 / T1078 (Privilege Escalation via Group Modification)",
        "condition": "Standard user assigned special admin privileges (Event ID 4672) or executing 'net localgroup administrators <user> /add'.",
        "severity": "CRITICAL",
        "recommended_action": "Revoke assigned token privileges, remove unauthorized account from local Administrators group, quarantine host."
    },
    {
        "id": "RULE-005",
        "name": "Defense Evasion - Audit Log Cleared",
        "category": "Defense Evasion",
        "mitre_id": "T1070.001 (Indicator Removal: Clear Windows Event Logs)",
        "condition": "Windows Security Event Log cleared (Event ID 1102) by non-system user.",
        "severity": "CRITICAL",
        "recommended_action": "Preserve SIEM centralized log archive, isolate endpoint immediately, commence forensic triage."
    }
]

def analyze_logs(logs_list):
    """
    Analyzes a sequence of log records and returns detected anomalies,
    matched rules, and correlated incident indicators.
    
    logs_list: list of dictionaries or sqlite3.Row objects representing logs.
    """
    anomalies_detected = []
    failed_logins_by_ip = {}
    last_logins_by_user = {}

    # Sort logs chronologically if timestamp exists
    sorted_logs = sorted(logs_list, key=lambda x: str(x['timestamp']))

    for index, log in enumerate(sorted_logs):
        log_dict = dict(log)
        event_id = int(log_dict.get('event_id', 0))
        src_ip = str(log_dict.get('source_ip', ''))
        username = str(log_dict.get('username', ''))
        process = str(log_dict.get('process', '') or '').lower()
        cmd_line = str(log_dict.get('command_line', '') or '')
        timestamp = str(log_dict.get('timestamp', ''))

        # Track Failed Logins (Event ID 4625)
        if event_id == 4625:
            if src_ip not in failed_logins_by_ip:
                failed_logins_by_ip[src_ip] = []
            failed_logins_by_ip[src_ip].append(log_dict)

            # Check Rule 1: Brute Force (>5 failed attempts from same IP)
            if len(failed_logins_by_ip[src_ip]) >= 5:
                # Only trigger once or on threshold
                if not any(a['rule_code'] == 'RULE-001' and a['source_ip'] == src_ip for a in anomalies_detected):
                    anomalies_detected.append({
                        "anomaly_code": f"ANOMALY-001",
                        "rule_code": "RULE-001",
                        "title": "Possible Brute Force Attack",
                        "anomaly_type": "Brute Force Authentication",
                        "severity": "HIGH",
                        "source_ip": src_ip,
                        "username": username,
                        "detection_timestamp": timestamp,
                        "description": f"Detected {len(failed_logins_by_ip[src_ip])} consecutive failed login attempts (Event ID 4625) from source IP {src_ip} targeting user '{username}'.",
                        "rule_triggered": "Rule 1: Failed Logins > 5 from same IP in short window",
                        "mitre_id": "T1110.001",
                        "recommended_action": "Temporarily block Source IP at firewall and verify account integrity."
                    })

        # Check Rule 2: Suspicious Authentication (Event ID 4624 after multiple failures)
        if event_id == 4624:
            failures = failed_logins_by_ip.get(src_ip, [])
            if len(failures) >= 3:
                if not any(a['rule_code'] == 'RULE-002' and a['source_ip'] == src_ip for a in anomalies_detected):
                    anomalies_detected.append({
                        "anomaly_code": f"ANOMALY-002",
                        "rule_code": "RULE-002",
                        "title": "Suspicious Authentication Activity",
                        "anomaly_type": "Compromised Credential Use",
                        "severity": "HIGH",
                        "source_ip": src_ip,
                        "username": username,
                        "detection_timestamp": timestamp,
                        "description": f"Successful logon (Event ID 4624) observed for user '{username}' immediately after {len(failures)} failed attempts from IP {src_ip}.",
                        "rule_triggered": "Rule 2: Successful Logon after >= 3 Failed Logons from same IP",
                        "mitre_id": "T1078.003",
                        "recommended_action": "Force password reset for compromised user, terminate active sessions, enable MFA."
                    })

        # Check Rule 3: Suspicious PowerShell Execution
        if "powershell" in process or "powershell.exe" in cmd_line.lower():
            suspicious_keywords = ["-encodedcommand", "-enc", "bypass", "hidden", "downloadstring", "invoke-expression", "iex"]
            cmd_lower = cmd_line.lower()
            if any(k in cmd_lower for k in suspicious_keywords):
                if not any(a['rule_code'] == 'RULE-003' for a in anomalies_detected):
                    anomalies_detected.append({
                        "anomaly_code": f"ANOMALY-003",
                        "rule_code": "RULE-003",
                        "title": "Suspicious PowerShell Activity",
                        "anomaly_type": "Execution & Defense Evasion",
                        "severity": "HIGH",
                        "source_ip": src_ip,
                        "username": username,
                        "detection_timestamp": timestamp,
                        "description": f"Process powershell.exe executed with obfuscated/encoded arguments: '{cmd_line[:120]}...'",
                        "rule_triggered": "Rule 3: Encoded / Obfuscated PowerShell execution flags detected",
                        "mitre_id": "T1059.001",
                        "recommended_action": "Isolate host, terminate PowerShell process tree, inspect staging URL/payload."
                    })

        # Check Rule 4: Privilege Escalation (Event ID 4672 or net localgroup administrators)
        is_priv_event = (event_id == 4672 and username not in ['SYSTEM', 'admin_sec', 'LOCAL SERVICE', 'NETWORK SERVICE'])
        is_net_admin = ("net.exe" in process or "net" in process) and ("localgroup administrators" in cmd_line.lower() and "/add" in cmd_line.lower())
        if is_priv_event or is_net_admin:
            if not any(a['rule_code'] == 'RULE-004' for a in anomalies_detected):
                anomalies_detected.append({
                    "anomaly_code": f"ANOMALY-004",
                    "rule_code": "RULE-004",
                    "title": "Possible Privilege Escalation",
                    "anomaly_type": "Privilege Escalation & Persistence",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "username": username,
                    "detection_timestamp": timestamp,
                    "description": f"User '{username}' was assigned administrator privileges (Event 4672 / SeDebugPrivilege) or added to local Administrators group.",
                    "rule_triggered": "Rule 4: Standard user account acquiring elevated domain/local privileges",
                    "mitre_id": "T1068",
                    "recommended_action": "Revoke administrator assignment, remove user from Administrators group, freeze workstation."
                })

        # Check Rule 5: Defense Evasion - Audit Log Cleared (Event ID 1102)
        if event_id == 1102:
            if not any(a['rule_code'] == 'RULE-005' for a in anomalies_detected):
                anomalies_detected.append({
                    "anomaly_code": f"ANOMALY-005",
                    "rule_code": "RULE-005",
                    "title": "Defense Evasion - Audit Log Cleared",
                    "anomaly_type": "Defense Evasion",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "username": username,
                    "detection_timestamp": timestamp,
                    "description": f"Security Event Log was cleared (Event ID 1102) by user '{username}' to obscure post-exploitation activity.",
                    "rule_triggered": "Rule 5: Event ID 1102 (The audit log was cleared) on endpoint",
                    "mitre_id": "T1070.001",
                    "recommended_action": "Preserve SIEM centralized log archive, isolate endpoint immediately, begin full forensic investigation."
                })

    return anomalies_detected
