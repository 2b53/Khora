"""
Nmap reconnaissance module for service discovery and result summarization.
"""

from datetime import datetime
import json
import logging
import os
import subprocess

logger = logging.getLogger("Khora.Nmap")


def full_nmap_scan(target):
    """Run the configured Nmap scan set."""
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    scans = [
        {
            "name": "Quick Service Scan",
            "cmd": [
                "nmap",
                "-sV",
                "-sC",
                "-Pn",
                "--top-ports",
                "1000",
                "-oN",
                f"results/nmap_quick_{timestamp}.txt",
                "-oX",
                f"results/nmap_quick_{timestamp}.xml",
                target,
            ],
        },
        {
            "name": "UDP Scan",
            "cmd": ["nmap", "-sU", "--top-ports", "100", "-Pn", "-oN", f"results/nmap_udp_{timestamp}.txt", target],
        },
        {
            "name": "Full TCP Port Scan",
            "cmd": ["nmap", "-sS", "-p-", "-Pn", "-oN", f"results/nmap_full_{timestamp}.txt", target],
        },
        {
            "name": "Vulnerability Scan",
            "cmd": [
                "nmap",
                "-sV",
                "-oN",
                f"results/nmap_vuln_{timestamp}.txt",
                "--script=vuln,default",
                target,
            ],
        },
        {
            "name": "SMB Enumeration",
            "cmd": [
                "nmap",
                "-p139,445",
                "--script=smb-enum*,smb-vuln*",
                "-oN",
                f"results/nmap_smb_{timestamp}.txt",
                target,
            ],
        },
        {
            "name": "FTP/SSH Service Scan",
            "cmd": ["nmap", "-p21,22", "--script=ftp*,ssh*", "-oN", f"results/nmap_ssh_ftp_{timestamp}.txt", target],
        },
        {
            "name": "HTTP/HTTPS Enumeration",
            "cmd": [
                "nmap",
                "-p80,443,8080,8443",
                "--script=http*,ssl*",
                "-oN",
                f"results/nmap_http_{timestamp}.txt",
                target,
            ],
        },
        {
            "name": "Database Service Scan",
            "cmd": [
                "nmap",
                "-p3306,5432,1433,27017,6379",
                "--script=mysql*,postgres*,oracle*,mongodb*",
                "-oN",
                f"results/nmap_db_{timestamp}.txt",
                target,
            ],
        },
        {
            "name": "OS Detection Scan",
            "cmd": ["nmap", "-O", "-sV", "-Pn", "-oN", f"results/nmap_os_{timestamp}.txt", target],
        },
    ]

    results_summary = []

    for scan in scans:
        try:
            print(f"\n[+] Running: {scan['name']}")
            print(f"    Output: {scan['cmd'][-2] if scan['cmd'][-2].startswith('results/') else scan['cmd'][-1]}")
            subprocess.run(scan["cmd"], check=True, capture_output=True, timeout=300)
            logger.info(f"Completed: {scan['name']}")
            results_summary.append({"scan": scan["name"], "status": "SUCCESS", "output": scan["cmd"][-2]})
        except subprocess.TimeoutExpired:
            logger.warning(f"{scan['name']} timeout")
            results_summary.append({"scan": scan["name"], "status": "TIMEOUT", "output": "N/A"})
        except FileNotFoundError:
            logger.error("nmap not found")
            print("[!] nmap is required but not installed")
            break
        except subprocess.CalledProcessError as exc:
            logger.warning(f"{scan['name']} failed: {exc}")
            results_summary.append({"scan": scan["name"], "status": "FAILED", "output": "N/A"})
        except Exception as exc:
            logger.error(f"Scan error: {exc}")

    summary_file = f"results/nmap_summary_{timestamp}.json"
    with open(summary_file, "w") as handle:
        json.dump({"target": target, "timestamp": timestamp, "scans": results_summary}, handle, indent=2)

    logger.info(f"Summary: {summary_file}")
    return summary_file


def parse_nmap_results(target):
    """Display a short preview of the latest text output."""
    latest_files = []
    for file_name in os.listdir("results"):
        if file_name.endswith(".txt"):
            latest_files.append(os.path.join("results", file_name))

    if latest_files:
        print("\n" + "=" * 70)
        print("RECON OUTPUT PREVIEW".center(70))
        print("=" * 70)
        latest = sorted(latest_files)[-1]
        with open(latest, "r") as handle:
            lines = handle.read().split("\n")[:50]
            for line in lines:
                print(line)
        print("\nFull results available in: results/")


def generate_assessment_notes(target):
    """Print follow-up notes for common service categories."""
    notes = f"""
======================================================================
ASSESSMENT FOLLOW-UP NOTES
======================================================================

[SSH / 22]
  - Review authentication methods and banner details
  - Check for weak credentials or exposed keys
  - Validate version-specific exposure

[FTP / 21]
  - Review anonymous access
  - Check credential hygiene and writable paths
  - Inspect service version and extension set

[SMB / 139,445]
  - Review signing, guest access, and share exposure
  - Validate MS17-010 exposure where relevant
  - Inspect enumeration output before deeper follow-up

[HTTP / HTTPS]
  - Review exposed applications and virtual hosts
  - Inspect technology fingerprinting results
  - Correlate with dedicated web validation steps

[DATABASE SERVICES]
  - Review network exposure and authentication posture
  - Inspect service versions and default configurations
  - Correlate with environment-specific controls

NEXT STEPS
1. Review the detailed files in results/
2. Correlate reachable services with the module registry
3. Select focused follow-up modules where justified
4. Preserve notable findings in the active session record
"""
    print(notes)


def run(target, lhost, lport=4444):
    """Module entrypoint."""
    print("\n" + "=" * 70)
    print("NMAP RECON MODULE".center(70))
    print("=" * 70)
    print(f"Target:   {target}")
    print(f"Listener: {lhost}:{lport}\n")

    logger.info(f"Starting reconnaissance scan on {target}")

    full_nmap_scan(target)
    parse_nmap_results(target)
    generate_assessment_notes(target)

    print("\n" + "=" * 70)
    print("RECON COMPLETE".center(70))
    print("Results saved to: results/".center(70))
    print("=" * 70 + "\n")

    logger.info(f"Nmap module complete for {target}")
