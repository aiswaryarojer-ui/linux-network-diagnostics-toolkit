"""
================================================================================
Linux & Network Diagnostics CLI Entrypoint
Author: Aiswarya Rojer
Description: Command-line interface for netdiag troubleshooting toolkit.
================================================================================
"""

import sys
import os
import argparse
import json
import logging

# Ensure netdiag package is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from netdiag.dns_checker import DNSChecker
from netdiag.network_checker import NetworkChecker
from netdiag.sys_analyzer import SystemAnalyzer
from netdiag.rca_generator import RCAGenerator

# Setup Console Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("netdiag.cli")


def run_diagnostics(target_host: str = "google.com", port: int = 443, log_path: str = None) -> RCAGenerator:
    """Execute complete diagnostic suite against target host and local operating system."""
    logger.info(f"Initiating NetDiag Troubleshooting Suite for Target: {target_host}:{port}")

    rca = RCAGenerator(target_hostname=target_host)

    # 1. DNS Diagnostics
    dns_tool = DNSChecker(timeout=3.0)
    dns_res = dns_tool.check_hostname_resolution(target_host)
    rca.add_dns_results(dns_res)

    # 2. Network Connectivity & SSL Check
    net_tool = NetworkChecker(timeout=3.0)
    conn_res = net_tool.check_port_connectivity(target_host, port)
    rca.add_network_result(conn_res)

    if port == 443 or "https" in target_host:
        ssl_res = net_tool.check_ssl_certificate(target_host, port)
        rca.add_ssl_result(ssl_res)

    # 3. System Resource & Log Inspection
    sys_tool = SystemAnalyzer(log_path=log_path or "/var/log/syslog")
    load_res = sys_tool.get_system_load()
    disk_res = sys_tool.get_disk_usage("/")
    
    # Scan custom log or local syslog if available
    log_res = sys_tool.scan_log_file(custom_log_path=log_path) if log_path and os.path.exists(log_path) else {
        "log_file": log_path or "None",
        "error_count": 0,
        "status": "OK"
    }
    
    rca.add_system_results(load_res, disk_res, log_res)

    return rca


def main():
    parser = argparse.ArgumentParser(
        description="NetDiag - Linux & Network Diagnostics Troubleshooting Toolkit by Aiswarya Rojer"
    )
    parser.add_argument("--host", default="google.com", help="Target hostname/IP for DNS & Network diagnostics")
    parser.add_argument("--port", type=int, default=443, help="Target TCP port (Default: 443)")
    parser.add_argument("--log-file", default=None, help="Path to system or application log file to scan")
    parser.add_argument("--output-rca", default=None, help="Output path to save Markdown Root Cause Analysis report")
    parser.add_argument("--json", action="store_true", help="Output diagnostic findings in JSON format")

    args = parser.parse_args()

    rca = run_diagnostics(target_host=args.host, port=args.port, log_path=args.log_file)
    report_md = rca.generate_markdown_report()

    if args.output_rca:
        with open(args.output_rca, "w", encoding="utf-8") as f:
            f.write(report_md)
        logger.info(f"Root Cause Analysis report successfully saved to: {args.output_rca}")

    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except AttributeError:
            pass

    if args.json:
        print(json.dumps(rca.findings, indent=2))
    else:
        try:
            print("\n" + report_md)
        except UnicodeEncodeError:
            print("\n" + report_md.encode("ascii", errors="replace").decode("ascii"))



if __name__ == "__main__":
    main()
