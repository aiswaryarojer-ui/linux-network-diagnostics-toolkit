"""
================================================================================
DNS Diagnostics Module
Author: Aiswarya Rojer
Description: Inspects DNS resolution performance, checks nameservers, verifies
             IP address mapping, and measures lookup latency.
================================================================================
"""

import socket
import time
import logging

logger = logging.getLogger("netdiag.dns")


class DNSChecker:
    """Performs DNS diagnostics and validation for given target hostnames."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def check_hostname_resolution(self, hostname: str) -> dict:
        """Resolve hostname to IPv4 and IPv6 addresses and measure query latency."""
        start_time = time.time()
        result = {
            "target": hostname,
            "resolved_ip": None,
            "all_ips": [],
            "latency_ms": None,
            "status": "FAIL",
            "error": None
        }

        try:
            socket.setdefaulttimeout(self.timeout)
            addresses = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            unique_ips = list(set([addr[4][0] for addr in addresses if addr[4]]))
            
            result["resolved_ip"] = unique_ips[0] if unique_ips else None
            result["all_ips"] = unique_ips
            result["latency_ms"] = elapsed_ms
            result["status"] = "OK"
            logger.info(f"DNS Resolution successful for {hostname}: {unique_ips} in {elapsed_ms}ms")

        except socket.gaierror as e:
            result["error"] = f"DNS Resolution Error (gaierror): {e.strerror or str(e)}"
            logger.error(f"DNS failure for {hostname}: {result['error']}")
        except socket.timeout:
            result["error"] = f"DNS Query Timed Out after {self.timeout}s"
            logger.error(f"DNS timeout for {hostname}")
        except Exception as e:
            result["error"] = f"Unexpected DNS error: {str(e)}"
            logger.error(f"Unexpected DNS error for {hostname}: {str(e)}")

        return result

    def inspect_nameservers(self, resolv_conf_path: str = "/etc/resolv.conf") -> dict:
        """Parse Linux /etc/resolv.conf to inspect configured nameservers and search domains."""
        summary = {
            "nameservers": [],
            "search_domains": [],
            "status": "OK",
            "warnings": []
        }

        try:
            with open(resolv_conf_path, "r") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        summary["nameservers"].append(parts[1])
                elif line.startswith("search") or line.startswith("domain"):
                    parts = line.split()
                    if len(parts) > 1:
                        summary["search_domains"].extend(parts[1:])

            if not summary["nameservers"]:
                summary["status"] = "WARNING"
                summary["warnings"].append("No nameservers found in /etc/resolv.conf")

            # Flag potential loopback-only DNS or localhost stub
            if summary["nameservers"] == ["127.0.0.1"] or summary["nameservers"] == ["127.0.0.53"]:
                summary["warnings"].append("Local DNS stub resolver active (127.0.0.1 / 127.0.0.53)")

        except FileNotFoundError:
            summary["status"] = "SKIPPED"
            summary["warnings"].append(f"File not found: {resolv_conf_path} (likely non-Linux host)")
        except Exception as e:
            summary["status"] = "FAIL"
            summary["warnings"].append(f"Failed reading {resolv_conf_path}: {str(e)}")

        return summary
