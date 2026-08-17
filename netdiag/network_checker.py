"""
================================================================================
Network & SSL/TLS Diagnostics Module
Author: Aiswarya Rojer
Description: Inspects TCP/UDP port reachability, HTTP status codes, latency,
             and SSL/TLS certificate validity & expiration.
================================================================================
"""

import socket
import ssl
import urllib.request
import urllib.error
import time
from datetime import datetime, timezone
import logging

logger = logging.getLogger("netdiag.network")


class NetworkChecker:
    """Performs socket connection tests, HTTP health checks, and SSL certificate audits."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def check_port_connectivity(self, host: str, port: int) -> dict:
        """Test TCP socket handshake latency to target host and port."""
        start_time = time.time()
        result = {
            "host": host,
            "port": port,
            "status": "FAIL",
            "latency_ms": None,
            "error": None
        }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            conn_res = sock.connect_ex((host, port))
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            if conn_res == 0:
                result["status"] = "OPEN"
                result["latency_ms"] = elapsed_ms
                logger.info(f"Port {port} on {host} is OPEN ({elapsed_ms}ms)")
            else:
                result["status"] = "CLOSED_OR_FILTERED"
                result["error"] = f"Socket connection failed with error code: {conn_res}"
                logger.warning(f"Port {port} on {host} is CLOSED/FILTERED (error {conn_res})")
        except Exception as e:
            result["error"] = f"Socket exception: {str(e)}"
            logger.error(f"Error checking port {port} on {host}: {str(e)}")
        finally:
            sock.close()

        return result

    def check_http_endpoint(self, url: str) -> dict:
        """Inspect HTTP/HTTPS response status code, latency, and headers."""
        start_time = time.time()
        result = {
            "url": url,
            "status_code": None,
            "latency_ms": None,
            "status": "FAIL",
            "error": None
        }

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetDiag-Troubleshooting-Toolkit/1.0"}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                result["status_code"] = response.getcode()
                result["latency_ms"] = elapsed_ms
                result["status"] = "OK" if response.getcode() < 400 else "FAIL"
                logger.info(f"HTTP GET {url} -> {response.getcode()} ({elapsed_ms}ms)")
        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            result["status_code"] = e.code
            result["latency_ms"] = elapsed_ms
            result["error"] = f"HTTP Error {e.code}: {e.reason}"
            logger.warning(f"HTTP GET {url} -> Error {e.code}")
        except urllib.error.URLError as e:
            result["error"] = f"URL Error: {e.reason}"
            logger.error(f"HTTP GET {url} failed: {e.reason}")
        except Exception as e:
            result["error"] = f"Request exception: {str(e)}"
            logger.error(f"HTTP GET {url} failed: {str(e)}")

        return result

    def check_ssl_certificate(self, hostname: str, port: int = 443) -> dict:
        """Retrieve and validate SSL/TLS certificate details, calculating days until expiry."""
        result = {
            "hostname": hostname,
            "port": port,
            "issuer": None,
            "subject": None,
            "expires_on": None,
            "days_remaining": None,
            "is_valid": False,
            "status": "FAIL",
            "warnings": [],
            "error": None
        }

        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Expiration Parsing
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        # Format: 'May 10 23:59:59 2026 GMT'
                        expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        days_left = (expires_dt - now_dt).days

                        result["expires_on"] = expires_dt.isoformat()
                        result["days_remaining"] = days_left
                        result["is_valid"] = days_left > 0

                        if days_left <= 0:
                            result["status"] = "EXPIRED"
                            result["error"] = f"SSL Certificate EXPIRED {abs(days_left)} days ago!"
                        elif days_left < 30:
                            result["status"] = "EXPIRING_SOON"
                            result["warnings"].append(f"SSL Certificate expires in {days_left} days!")
                        else:
                            result["status"] = "OK"

                    # Issuer Details
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
                    result["subject"] = subject.get("commonName", hostname)

                    logger.info(f"SSL Cert for {hostname}: Valid={result['is_valid']}, Days left={result['days_remaining']}")

        except ssl.SSLCertVerificationError as e:
            result["error"] = f"SSL Verification Failed: {e.strerror or str(e)}"
            result["status"] = "INVALID"
            logger.error(f"SSL Verification error for {hostname}: {result['error']}")
        except Exception as e:
            result["error"] = f"SSL Handshake error: {str(e)}"
            logger.error(f"SSL handshake error for {hostname}: {str(e)}")

        return result
