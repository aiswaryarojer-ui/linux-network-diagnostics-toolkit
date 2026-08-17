"""
================================================================================
Root Cause Analysis (RCA) Generator Module
Author: Aiswarya Rojer
Description: Compiles diagnostic findings across DNS, Network, SSL, and System
             modules into structured Markdown/HTML Root Cause Analysis reports.
================================================================================
"""

import json
from datetime import datetime, timezone


class RCAGenerator:
    """Aggregates diagnostic results and generates formatted Root Cause Analysis reports."""

    def __init__(self, target_hostname: str = "localhost"):
        self.target_hostname = target_hostname
        self.findings = {
            "dns": {},
            "network": [],
            "ssl": {},
            "system_load": {},
            "disk": {},
            "logs": {}
        }

    def add_dns_results(self, dns_data: dict):
        self.findings["dns"] = dns_data

    def add_network_result(self, net_data: dict):
        self.findings["network"].append(net_data)

    def add_ssl_result(self, ssl_data: dict):
        self.findings["ssl"] = ssl_data

    def add_system_results(self, load_data: dict, disk_data: dict, log_data: dict):
        self.findings["system_load"] = load_data
        self.findings["disk"] = disk_data
        self.findings["logs"] = log_data

    def calculate_health_score(self) -> tuple[int, list, list]:
        """Calculate system health score (0-100%) and identify primary root causes."""
        score = 100
        root_causes = []
        recommendations = []

        # 1. DNS Assessment
        dns_res = self.findings.get("dns", {})
        if dns_res.get("status") != "OK" and dns_res.get("error"):
            score -= 30
            root_causes.append(f"DNS Resolution Failure: {dns_res.get('error')}")
            recommendations.append("Check DNS resolver configuration in /etc/resolv.conf and verify upstream nameserver reachability.")

        # 2. Network Port Assessment
        for net in self.findings.get("network", []):
            if net.get("status") not in ["OK", "OPEN"]:
                score -= 20
                root_causes.append(f"Port Connectivity Failure on {net.get('host')}:{net.get('port')} ({net.get('status')})")
                recommendations.append(f"Verify firewall rules (iptables/ufw), Security Groups, and check if target process is listening on port {net.get('port')}.")

        # 3. SSL Certificate Assessment
        ssl_res = self.findings.get("ssl", {})
        if ssl_res.get("status") in ["EXPIRED", "INVALID"]:
            score -= 25
            root_causes.append(f"SSL Certificate Failure: {ssl_res.get('error')}")
            recommendations.append("Renew TLS/SSL certificate using Let's Encrypt certbot or update private CA bundle.")
        elif ssl_res.get("status") == "EXPIRING_SOON":
            score -= 10
            root_causes.append(f"SSL Certificate Expiring Soon ({ssl_res.get('days_remaining')} days left)")
            recommendations.append("Schedule TLS certificate renewal before expiration.")

        # 4. Disk Capacity Assessment
        disk_res = self.findings.get("disk", {})
        if disk_res.get("status") == "CRITICAL":
            score -= 25
            root_causes.append(f"Disk Capacity Critical: {disk_res.get('percent_used')}% used on partition '{disk_res.get('path')}'")
            recommendations.append("Clear log files (/var/log), purge temporary files, or expand EBS volume partition.")

        # 5. Log Error Assessment
        log_res = self.findings.get("logs", {})
        if log_res.get("status") == "ERRORS_DETECTED":
            score -= 15
            root_causes.append(f"System Log Errors Detected: {log_res.get('error_count')} critical log entries found")
            recommendations.append(f"Inspect system log entries in {log_res.get('log_file')} for detailed application tracebacks.")

        score = max(0, score)
        return score, root_causes, recommendations

    def generate_markdown_report(self) -> str:
        """Render a clean Markdown Root Cause Analysis report."""

        health_score, root_causes, recommendations = self.calculate_health_score()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        status_badge = "🟢 HEALTHY" if health_score >= 80 else ("🟡 DEGRADED" if health_score >= 50 else "🔴 CRITICAL INCIDENT")

        md = f"""# Root Cause Analysis (RCA) Report

**Target Host:** `{self.target_hostname}`  
**Generated At:** `{timestamp}`  
**System Health Score:** `{health_score}%`  
**Overall System Status:** {status_badge}  

---

## 🚨 Primary Root Cause & Findings

"""
        if root_causes:
            for idx, cause in enumerate(root_causes, 1):
                md += f"{idx}. ❌ **{cause}**\n"
        else:
            md += "✅ No critical failure indicators detected during inspection.\n"

        md += "\n## 💡 Recommended Remediation Actions\n\n"
        if recommendations:
            for idx, rec in enumerate(recommendations, 1):
                md += f"{idx}. 🔧 {rec}\n"
        else:
            md += "✅ System performing within optimal operational thresholds. No corrective action needed.\n"

        md += f"""
---

## 🔍 Detailed Diagnostic Inspection Breakdown

### 1. DNS Resolution Audit
* **Host:** `{self.findings.get('dns', {}).get('target', 'N/A')}`
* **Status:** `{self.findings.get('dns', {}).get('status', 'N/A')}`
* **Resolved IP:** `{self.findings.get('dns', {}).get('resolved_ip', 'N/A')}`
* **Query Latency:** `{self.findings.get('dns', {}).get('latency_ms', 'N/A')} ms`
"""

        if self.findings.get('ssl'):
            ssl_info = self.findings['ssl']
            md += f"""
### 2. SSL/TLS Certificate Audit
* **Issuer:** `{ssl_info.get('issuer', 'N/A')}`
* **Expires On:** `{ssl_info.get('expires_on', 'N/A')}`
* **Days Remaining:** `{ssl_info.get('days_remaining', 'N/A')} days`
* **Status:** `{ssl_info.get('status', 'N/A')}`
"""

        if self.findings.get('disk'):
            disk_info = self.findings['disk']
            md += f"""
### 3. Disk Resource Utilization
* **Partition:** `{disk_info.get('path', '/')}`
* **Capacity Used:** `{disk_info.get('percent_used', 0)}%` ({disk_info.get('used_gb', 0)} GB / {disk_info.get('total_gb', 0)} GB)
* **Status:** `{disk_info.get('status', 'OK')}`
"""

        md += """
---
*Report generated automatically by NetDiag Troubleshooting Toolkit | Author: Aiswarya Rojer*
"""
        return md
