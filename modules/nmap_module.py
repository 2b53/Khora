# modules/nmap_module.py
"""
Nmap Module - Advanced Network Scanning & Reconnaissance
"""

import subprocess
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("Khora.Nmap")

def full_nmap_scan(target):
    """Comprehensive Nmap reconnaissance"""
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    scans = [
        # Quick TCP scan with version detection
        {
            'name': 'Quick Service Scan',
            'cmd': ["nmap", "-sV", "-sC", "-Pn", "--top-ports", "1000",
                   "-oN", f"results/nmap_quick_{timestamp}.txt",
                   "-oX", f"results/nmap_quick_{timestamp}.xml",
                   target]
        },
        # UDP scan
        {
            'name': 'UDP Scan',
            'cmd': ["nmap", "-sU", "--top-ports", "100", "-Pn",
                   "-oN", f"results/nmap_udp_{timestamp}.txt",
                   target]
        },
        # Full port scan
        {
            'name': 'Full TCP Port Scan',
            'cmd': ["nmap", "-sS", "-p-", "-Pn", 
                   "-oN", f"results/nmap_full_{timestamp}.txt",
                   target]
        },
        # Vulnerability scan with NSE scripts
        {
            'name': 'Vulnerability Scan',
            'cmd': ["nmap", "-sV", "-oN", f"results/nmap_vuln_{timestamp}.txt",
                   "--script=vuln,default", target]
        },
        # SMB enumeration
        {
            'name': 'SMB Enumeration',
            'cmd': ["nmap", "-p139,445", "--script=smb-enum*,smb-vuln*",
                   "-oN", f"results/nmap_smb_{timestamp}.txt",
                   target]
        },
        # FTP/SSH enumeration
        {
            'name': 'FTP/SSH Service Scan',
            'cmd': ["nmap", "-p21,22", "--script=ftp*,ssh*",
                   "-oN", f"results/nmap_ssh_ftp_{timestamp}.txt",
                   target]
        },
        # HTTP/HTTPS enumeration
        {
            'name': 'HTTP/HTTPS Enumeration',
            'cmd': ["nmap", "-p80,443,8080,8443", "--script=http*,ssl*",
                   "-oN", f"results/nmap_http_{timestamp}.txt",
                   target]
        },
        # Database services
        {
            'name': 'Database Service Scan',
            'cmd': ["nmap", "-p3306,5432,1433,27017,6379", 
                   "--script=mysql*,postgres*,oracle*,mongodb*",
                   "-oN", f"results/nmap_db_{timestamp}.txt",
                   target]
        },
        # OS detection
        {
            'name': 'OS Detection Scan',
            'cmd': ["nmap", "-O", "-sV", "-Pn",
                   "-oN", f"results/nmap_os_{timestamp}.txt",
                   target]
        }
    ]
    
    results_summary = []
    
    for scan in scans:
        try:
            print(f"\n[+] Running: {scan['name']}")
            print(f"    Command: {' '.join(scan['cmd'][-3:])}")
            subprocess.run(scan['cmd'], check=True, capture_output=True, timeout=300)
            logger.info(f"Completed: {scan['name']}")
            results_summary.append({
                'scan': scan['name'],
                'status': 'SUCCESS',
                'output': scan['cmd'][-2]
            })
        except subprocess.TimeoutExpired:
            logger.warning(f"{scan['name']} timeout")
            results_summary.append({
                'scan': scan['name'],
                'status': 'TIMEOUT',
                'output': 'N/A'
            })
        except FileNotFoundError:
            logger.error("nmap not found - install: apt install nmap")
            print("[!] nmap is required but not installed")
            break
        except subprocess.CalledProcessError as e:
            logger.warning(f"{scan['name']} failed: {e}")
            results_summary.append({
                'scan': scan['name'],
                'status': 'FAILED',
                'output': 'N/A'
            })
        except Exception as e:
            logger.error(f"Scan error: {e}")
    
    # Create summary report
    summary_file = f"results/nmap_summary_{timestamp}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            'target': target,
            'timestamp': timestamp,
            'scans': results_summary
        }, f, indent=2)
    
    logger.info(f"Summary: {summary_file}")
    return summary_file

def parse_nmap_results(target):
    """Parse and display nmap results"""
    results_dir = "results"
    latest_files = []
    
    # Find latest nmap results
    for file in os.listdir(results_dir):
        if file.endswith('.txt'):
            latest_files.append(os.path.join(results_dir, file))
    
    if latest_files:
        print("\n" + "="*70)
        print("SCAN RESULTS".center(70))
        print("="*70)
        latest = sorted(latest_files)[-1]
        with open(latest, 'r') as f:
            content = f.read()
            # Show first 50 lines
            lines = content.split('\n')[:50]
            for line in lines:
                print(line)
        print("\nFull results in: results/")

def generate_exploitation_recommendations(target):
    """Generate exploitation recommendations based on services found"""
    recommendations = """
╔═══════════════════════════════════════════════════════════╗
║         EXPLOITATION RECOMMENDATIONS                      ║
╚═══════════════════════════════════════════════════════════╝

COMMON EXPLOITATION PATHS:

[SSH (Port 22)]
  └─ Brute force credentials
  └─ Check for weak keys
  └─ Look for unpatched versions

[FTP (Port 21)]
  └─ Anonymous login attempts
  └─ Weak credentials
  └─ Buffer overflow exploits

[SMB (Port 139/445)]
  └─ EternalBlue (MS17-010) - Windows
  └─ Null session enumeration
  └─ Relay attacks

[HTTP/HTTPS (Port 80/443)]
  └─ Web application vulnerabilities
  └─ Directory traversal
  └─ RCE exploits (Struts2, Log4Shell)

[Database Services (3306, 5432, 1433, 27017, 6379)]
  └─ Weak authentication
  └─ SQL injection
  └─ Command injection

NEXT STEPS:
1. Review detailed scan results in: results/
2. Identify active services and versions
3. Check moduleS for specific exploits
4. Run backdoor module to generate payloads
5. Use C2 module to establish communication

"""
    print(recommendations)

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Network Scanning"""
    print("\n" + "="*70)
    print("NMAP RECONNAISSANCE MODULE".center(70))
    print("="*70)
    print(f"Target: {target}")
    print(f"Listener: {lhost}:{lport}\n")
    
    logger.info(f"Starting comprehensive scan on {target}")
    
    summary = full_nmap_scan(target)
    parse_nmap_results(target)
    generate_exploitation_recommendations(target)
    
    print("\n" + "="*70)
    print(f"Scan complete - Results saved to: results/")
    print("="*70 + "\n")
    
    logger.info(f"Nmap module complete for {target}")
