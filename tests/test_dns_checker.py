"""
================================================================================
Unit Tests for DNS Diagnostics Module
================================================================================
"""

import sys
import os
import unittest
import socket
from unittest.mock import patch


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netdiag.dns_checker import DNSChecker


class TestDNSChecker(unittest.TestCase):

    def setUp(self):
        self.checker = DNSChecker(timeout=2.0)

    @patch("socket.getaddrinfo")
    def test_check_hostname_resolution_success(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.180.206", 80))
        ]

        result = self.checker.check_hostname_resolution("google.com")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["resolved_ip"], "142.250.180.206")
        self.assertIsNotNone(result["latency_ms"])

    @patch("socket.getaddrinfo")
    def test_check_hostname_resolution_gaierror(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror(-2, "Name or service not known")

        result = self.checker.check_hostname_resolution("nonexistent-domain-xyz123.com")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("Name or service not known", result["error"])

    def test_inspect_nameservers_fallback(self):
        result = self.checker.inspect_nameservers("/nonexistent/path/resolv.conf")
        self.assertEqual(result["status"], "SKIPPED")


if __name__ == "__main__":
    unittest.main()
