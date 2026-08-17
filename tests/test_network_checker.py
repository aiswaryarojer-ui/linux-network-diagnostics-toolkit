"""
================================================================================
Unit Tests for Network & SSL Diagnostics Module
================================================================================
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netdiag.network_checker import NetworkChecker


class TestNetworkChecker(unittest.TestCase):

    def setUp(self):
        self.checker = NetworkChecker(timeout=2.0)

    @patch("socket.socket")
    def test_check_port_connectivity_open(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        res = self.checker.check_port_connectivity("127.0.0.1", 80)
        self.assertEqual(res["status"], "OPEN")
        self.assertIsNotNone(res["latency_ms"])

    @patch("socket.socket")
    def test_check_port_connectivity_closed(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111 # Connection refused
        mock_socket_cls.return_value = mock_sock

        res = self.checker.check_port_connectivity("127.0.0.1", 9999)
        self.assertEqual(res["status"], "CLOSED_OR_FILTERED")

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_check_ssl_certificate_valid(self, mock_conn, mock_ssl_ctx):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "notAfter": "May 10 23:59:59 2030 GMT",
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "subject": ((("commonName", "example.com"),),)
        }
        mock_ssl_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        res = self.checker.check_ssl_certificate("example.com", 443)
        self.assertEqual(res["status"], "OK")
        self.assertTrue(res["is_valid"])
        self.assertGreater(res["days_remaining"], 100)


if __name__ == "__main__":
    unittest.main()
