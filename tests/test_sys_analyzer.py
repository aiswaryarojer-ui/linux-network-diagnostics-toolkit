"""
================================================================================
Unit Tests for System Resource & Log Analyzer Module
================================================================================
"""

import sys
import os
import unittest
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netdiag.sys_analyzer import SystemAnalyzer


class TestSystemAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SystemAnalyzer()

    def test_scan_log_file_with_mock_errors(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write("INFO: System startup clean\n")
            tmp.write("ERROR: OOM-killer triggered on mysqld\n")
            tmp.write("CRITICAL: Disk full - No space left on device\n")
            tmp_path = tmp.name

        try:
            res = self.analyzer.scan_log_file(custom_log_path=tmp_path)
            self.assertEqual(res["status"], "ERRORS_DETECTED")
            self.assertEqual(res["error_count"], 2)
            self.assertEqual(len(res["matched_events"]), 2)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_scan_log_file_not_found(self):
        res = self.analyzer.scan_log_file(custom_log_path="/path/does/not/exist.log")
        self.assertEqual(res["status"], "FILE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
