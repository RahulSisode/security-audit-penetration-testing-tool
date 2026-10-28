"""
Unit tests for Integrations modules.
"""

import unittest
import json
import tempfile
import os

from integrations.report_parser import parse_security_alerts
from integrations.remediation_generator import generate_remediation_payload
from integrations.scanner_orchestrator import execute_infrastructure_map


class TestIntegrations(unittest.TestCase):

    def test_remediation_generator_csp(self):
        payload = generate_remediation_payload("Missing Content Security Policy (CSP) Header")
        self.assertEqual(payload["type"], "HTTP Header")
        self.assertIn("Content-Security-Policy", payload["nginx"])
        self.assertIn("Content-Security-Policy", payload["apache"])

    def test_remediation_generator_cookie(self):
        payload = generate_remediation_payload("Cookie No HttpOnly Flag")
        self.assertEqual(payload["type"], "Application Code Patch")
        self.assertIn("SESSION_COOKIE_HTTPONLY", payload["django_settings"])
        self.assertIn("httpOnly: true", payload["express_js"])

    def test_report_parser(self):
        sample_report = {
            "site": [
                {
                    "@name": "https://example.com",
                    "alerts": [
                        {
                            "alert": "Missing Anti-clickjacking Header",
                            "riskcode": "2",
                            "desc": "The response does not include either Content-Security-Policy with 'frame-ancestors' directive or a X-Frame-Options to protect against 'ClickJacking' attacks.",
                            "instances": [
                                {"uri": "https://example.com/login"}
                            ]
                        }
                    ]
                }
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(sample_report, tf)
            tf_path = tf.name

        try:
            alerts = parse_security_alerts(tf_path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["title"], "Missing Anti-clickjacking Header")
            self.assertEqual(alerts[0]["severity"], "MEDIUM")
            self.assertEqual(alerts[0]["target_uri"], "https://example.com/login")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_infrastructure_map_structure(self):
        # Test loopback without network requirement
        res = execute_infrastructure_map("127.0.0.1", ports=[])
        self.assertEqual(res["target"], "127.0.0.1")
        self.assertEqual(res["resolved_ip"], "127.0.0.1")
        self.assertEqual(res["ports"], [])


if __name__ == "__main__":
    unittest.main()
