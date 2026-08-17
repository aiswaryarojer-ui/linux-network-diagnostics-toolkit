"""
================================================================================
Unit Tests for Root Cause Analysis (RCA) Report Generator Module
================================================================================
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netdiag.rca_generator import RCAGenerator


class TestRCAGenerator(unittest.TestCase):

    def test_calculate_health_score_healthy(self):
        rca = RCAGenerator("localhost")
        rca.add_dns_results({"status": "OK", "resolved_ip": "127.0.0.1", "latency_ms": 5})
        rca.add_network_result({"host": "localhost", "port": 80, "status": "OPEN"})
        rca.add_ssl_result({"status": "OK", "days_remaining": 120})
        rca.add_system_results({"status": "OK"}, {"status": "OK"}, {"status": "OK"})

        score, causes, recs = rca.calculate_health_score()
        self.assertEqual(score, 100)
        self.assertEqual(len(causes), 0)

    def test_calculate_health_score_critical(self):
        rca = RCAGenerator("broken-node.local")
        rca.add_dns_results({"status": "FAIL", "error": "DNS Resolution Timeout"})
        rca.add_network_result({"host": "broken-node.local", "port": 443, "status": "CLOSED_OR_FILTERED"})
        rca.add_ssl_result({"status": "EXPIRED", "error": "SSL Certificate EXPIRED"})
        rca.add_system_results({"status": "HIGH_LOAD"}, {"status": "CRITICAL", "percent_used": 95}, {"status": "ERRORS_DETECTED", "error_count": 5})

        score, causes, recs = rca.calculate_health_score()
        self.assertLessEqual(score, 20)
        self.assertGreater(len(causes), 2)

        report_md = rca.generate_markdown_report()
        self.assertIn("Root Cause Analysis (RCA) Report", report_md)
        self.assertIn("DNS Resolution Failure", report_md)


if __name__ == "__main__":
    unittest.main()
