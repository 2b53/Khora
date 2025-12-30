# modules/nmap_module.py
import subprocess
import os

def full_nmap_scan(target):
    """Comprehensive Nmap recon"""
    os.makedirs("results", exist_ok=True)
    
    scans = [
        # Quick ports
        ["nmap", "-sV", "-sC", "-Pn", "-oN", "results/nmap-quick.txt", target],
        # UDP scan
        ["nmap", "-sU", "--top-ports", "100", "-Pn", "-oN", "results/nmap-udp.txt", target],
        # Vuln scan
        ["nmap", "-sV", "--script=vuln", "-oN", "results/nmap-vulns.txt", target],
        # SMB enum
        ["nmap", "-p445", "--script=smb*", "-oN", "results/nmap-smb.txt", target]
    ]
    
    for scan in scans:
        try:
            print(f"[+] Running: {' '.join(scan[-4:])}")
            subprocess.run(scan, check=True)
        except:
            print(f"[!] {scan[-1]} failed/skipped")
    
    print("[+] Nmap results: results/nmap-*.txt")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Nmap Recon"""
    print(f"[+] Nmap module: Full recon on {target}")
    full_nmap_scan(target)
    print("[+] Recon complete: results/nmap-*.txt")