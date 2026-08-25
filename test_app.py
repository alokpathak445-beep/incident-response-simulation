"""
test_app.py - Automated Verification Suite for Cybersecurity Incident Response Simulation
Tests database initialization, detection engine, Flask routes, and REST APIs.
"""

import unittest
import json
import os
from app import app, get_db_connection, init_db
from detector import analyze_logs, DETECTION_RULES

class TestCybersecuritySimulation(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        init_db(force_reseed=True)

    def test_database_seeded_properly(self):
        conn = get_db_connection()
        logs_count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        anomalies_count = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
        iocs_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        actions_count = conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0]
        conn.close()

        self.assertGreaterEqual(logs_count, 30, "Should have at least 30 simulated log records")
        self.assertGreaterEqual(anomalies_count, 4, "Should have at least 4 rule anomalies")
        self.assertGreaterEqual(iocs_count, 6, "Should have at least 6 IOCs")
        self.assertGreaterEqual(actions_count, 6, "Should have response actions")

    def test_detector_rules(self):
        conn = get_db_connection()
        logs = conn.execute("SELECT * FROM logs").fetchall()
        conn.close()

        anomalies = analyze_logs(logs)
        self.assertGreaterEqual(len(anomalies), 4, "Detection engine should identify attack chain anomalies")
        
        rule_codes = [a['rule_code'] for a in anomalies]
        self.assertIn('RULE-001', rule_codes, "Should detect Brute Force (Rule 1)")
        self.assertIn('RULE-002', rule_codes, "Should detect Suspicious Auth (Rule 2)")
        self.assertIn('RULE-003', rule_codes, "Should detect Suspicious PowerShell (Rule 3)")
        self.assertIn('RULE-004', rule_codes, "Should detect Privilege Escalation (Rule 4)")

    def test_page_routes(self):
        routes = [
            '/',
            '/dashboard',
            '/logs',
            '/anomalies',
            '/iocs',
            '/incidents',
            '/incident/INC-2026-001',
            '/response',
            '/report/INC-2026-001'
        ]
        for route in routes:
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200, f"Route {route} failed with status {response.status_code}")
            self.assertIn(b"Cybersecurity Incident Response Simulation", response.data, f"Footer missing on {route}")

    def test_logs_filtering(self):
        # Filter by severity HIGH
        res_high = self.client.get('/logs?severity=HIGH')
        self.assertEqual(res_high.status_code, 200)

        # Filter by Event ID 4625
        res_event = self.client.get('/logs?event_id=4625')
        self.assertEqual(res_event.status_code, 200)

        # Filter by IP
        res_ip = self.client.get('/logs?ip=192.168.10.45')
        self.assertEqual(res_ip.status_code, 200)

        # Filter by search
        res_search = self.client.get('/logs?q=powershell')
        self.assertEqual(res_search.status_code, 200)

    def test_rest_api_endpoints(self):
        # 1. /api/stats
        res = self.client.get('/api/stats')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn('timeline', data)
        self.assertIn('severity', data)

        # 2. /api/response_actions/update
        conn = get_db_connection()
        action_id = conn.execute("SELECT id FROM response_actions LIMIT 1").fetchone()[0]
        conn.close()

        res_update = self.client.post(
            '/api/response_actions/update',
            json={'action_id': action_id, 'status': 'Completed'}
        )
        self.assertEqual(res_update.status_code, 200)
        update_data = json.loads(res_update.data)
        self.assertTrue(update_data['success'])

        # 3. /api/response_actions/execute_simulation
        res_exec = self.client.post(
            '/api/response_actions/execute_simulation',
            json={'action_id': action_id}
        )
        self.assertEqual(res_exec.status_code, 200)
        exec_data = json.loads(res_exec.data)
        self.assertTrue(exec_data['success'])
        self.assertIn('result_log', exec_data)

        # 4. /api/incident/INC-2026-001/notes
        res_note = self.client.post(
            '/api/incident/INC-2026-001/notes',
            json={
                'author': 'Tester',
                'note_type': 'Observation',
                'note_text': 'Automated unit test note'
            }
        )
        self.assertEqual(res_note.status_code, 200)

        # 5. /api/reset_simulation
        res_reset = self.client.post('/api/reset_simulation')
        self.assertEqual(res_reset.status_code, 200)

if __name__ == '__main__':
    unittest.main()
