"""
================================================================================
Simulated Failure Lab Generator
Author: Aiswarya Rojer
Description: Generates mock system logs, simulated broken DNS entries, and
             faulty server responses for testing and demonstrating netdiag.
================================================================================
"""

import os
import sys

SAMPLE_BROKEN_SYSLOG = """
2026-08-17T18:00:01Z server-node-01 systemd[1]: Starting Network Manager...
2026-08-17T18:00:15Z server-node-01 kernel: [ 102.4512] Out of memory: Kill process 4102 (mysqld) score 750 or sacrifice child
2026-08-17T18:00:16Z server-node-01 kernel: [ 102.4515] OOM-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0
2026-08-17T18:01:05Z server-node-01 nginx[1204]: 2026/08/17 18:01:05 [error] 1204#0: *1 connect() failed (111: Connection refused) while connecting to upstream
2026-08-17T18:02:22Z server-node-01 systemd-journald[312]: Suppressed 42 messages from /system.slice/cron.service
2026-08-17T18:03:00Z server-node-01 storage-agent[901]: ERROR: Disk full - No space left on device (/var/log)
"""


def create_simulated_failure_environment(output_dir: str) -> str:
    """Generate a simulated broken syslog file inside the target directory."""
    os.makedirs(output_dir, exist_ok=True)
    log_file_path = os.path.join(output_dir, "simulated_broken_syslog.log")

    with open(log_file_path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_BROKEN_SYSLOG.strip())

    print(f"[+] Created simulated broken log environment at: {log_file_path}")
    return log_file_path


if __name__ == "__main__":
    target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "mock_environment"))
    create_simulated_failure_environment(target_dir)
