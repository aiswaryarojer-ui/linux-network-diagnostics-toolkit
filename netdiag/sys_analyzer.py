"""
================================================================================
Linux System & Resource Analyzer Module
Author: Aiswarya Rojer
Description: Inspects CPU load average, RAM utilization, disk space, and parses
             syslog/journalctl log outputs for high-severity critical errors.
================================================================================
"""

import os
import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger("netdiag.sys_analyzer")


class SystemAnalyzer:
    """Evaluates Linux operating system metrics and scans log files for critical errors."""

    def __init__(self, log_path: str = "/var/log/syslog"):
        self.log_path = log_path
        self.critical_patterns = [
            r"OOM-killer",
            r"out of memory",
            r"Kernel panic",
            r"Connection refused",
            r"Disk full|No space left on device",
            r"FAILED|ERROR|CRITICAL",
            r"Segmentation fault"
        ]

    def get_system_load(self) -> dict:
        """Fetch 1-min, 5-min, and 15-min CPU load average."""
        result = {
            "load_1m": 0.0,
            "load_5m": 0.0,
            "load_15m": 0.0,
            "cpu_count": os.cpu_count() or 1,
            "status": "OK",
            "warnings": []
        }

        try:
            if hasattr(os, "getloadavg"):
                load1, load5, load15 = os.getloadavg()
                result["load_1m"] = round(load1, 2)
                result["load_5m"] = round(load5, 2)
                result["load_15m"] = round(load15, 2)

                # Flag high load if 1-min load exceeds CPU core count * 1.5
                if load1 > (result["cpu_count"] * 1.5):
                    result["status"] = "HIGH_LOAD"
                    result["warnings"].append(f"CPU load average ({load1}) exceeds total CPU cores ({result['cpu_count']})!")
            else:
                # Fallback for systems without getloadavg
                result["status"] = "UNSUPPORTED"
                result["warnings"].append("os.getloadavg() not available on host OS")
        except Exception as e:
            result["status"] = "FAIL"
            result["warnings"].append(f"Failed fetching load avg: {str(e)}")

        return result

    def get_disk_usage(self, path: str = "/") -> dict:
        """Inspect disk partition capacity, used bytes, and free percentage."""
        result = {
            "path": path,
            "total_gb": 0.0,
            "used_gb": 0.0,
            "free_gb": 0.0,
            "percent_used": 0.0,
            "status": "OK",
            "warnings": []
        }

        try:
            if hasattr(os, "statvfs"):
                stat = os.statvfs(path)
                total = (stat.f_blocks * stat.f_frsize)
                free = (stat.f_bavail * stat.f_frsize)
                used = total - free
                percent = round((used / total) * 100, 2) if total > 0 else 0.0

                result["total_gb"] = round(total / (1024**3), 2)
                result["used_gb"] = round(used / (1024**3), 2)
                result["free_gb"] = round(free / (1024**3), 2)
                result["percent_used"] = percent

                if percent >= 90.0:
                    result["status"] = "CRITICAL"
                    result["warnings"].append(f"Disk partition '{path}' is CRITICALLY FULL ({percent}% used)!")
                elif percent >= 80.0:
                    result["status"] = "WARNING"
                    result["warnings"].append(f"Disk partition '{path}' usage high ({percent}% used).")
            else:
                result["status"] = "SKIPPED"
                result["warnings"].append("statvfs not available on non-POSIX OS")
        except Exception as e:
            result["status"] = "FAIL"
            result["warnings"].append(f"Disk check error for '{path}': {str(e)}")

        return result

    def scan_log_file(self, custom_log_path: str = None, max_lines: int = 500) -> dict:
        """Scan system logs for error patterns and output matched incident lines."""
        target_path = custom_log_path or self.log_path
        summary = {
            "log_file": target_path,
            "total_lines_scanned": 0,
            "error_count": 0,
            "matched_events": [],
            "status": "OK"
        }

        if not os.path.exists(target_path):
            summary["status"] = "FILE_NOT_FOUND"
            summary["matched_events"].append(f"Log file not found: {target_path}")
            return summary

        try:
            combined_pattern = re.compile("|".join(self.critical_patterns), re.IGNORECASE)

            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-max_lines:] # Scan recent lines
                summary["total_lines_scanned"] = len(lines)

                for idx, line in enumerate(lines, 1):
                    line_clean = line.strip()
                    if combined_pattern.search(line_clean):
                        summary["error_count"] += 1
                        summary["matched_events"].append({
                            "line_num": idx,
                            "content": line_clean[:200] # Truncate long log lines
                        })

            if summary["error_count"] > 0:
                summary["status"] = "ERRORS_DETECTED"

            logger.info(f"Scanned {summary['total_lines_scanned']} lines in {target_path}. Found {summary['error_count']} critical entries.")

        except Exception as e:
            summary["status"] = "FAIL"
            summary["matched_events"].append(f"Log parsing error: {str(e)}")
            logger.error(f"Error parsing log file {target_path}: {str(e)}")

        return summary
