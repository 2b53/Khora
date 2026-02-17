# KHORA Setup Guide

## Prerequisites Installation

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    nmap netcat-openbsd curl wget git gcc \
    build-essential libssl-dev

# Optional: Metasploit Framework
sudo apt install -y metasploit-framework

# Optional: Hashcat for hash cracking
sudo apt install -y hashcat

# Download rockyou wordlist
mkdir -p wordlists
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
mv rockyou.txt wordlists/
```

### Windows (WSL2 or VM)
```powershell
# Install Python 3.8+
# Download from python.org or use Windows Store

# Install dependencies
pip install --upgrade pip
pip install scapy requests pycryptodome
```

### macOS
```bash
brew install python3 nmap netcat wget git gcc
pip3 install -r requirements.txt
```

---

## Khora Installation

```bash
# Clone repository
git clone <repo-url> khora
cd khora

# Create virtual environment
python3 -m venv venv

# Activate environment
# Linux/Mac:
source venv/bin/activate

# Windows:
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 client.py --list
```

---

## Directory Setup

```bash
mkdir -p khora/{payloads,results,logs,exploits}
cd khora
chmod +x client.py
```

---

## Quick Test Run

### Verify Module Loading
```bash
python3 client.py --list
```

### Test on Local Network (HTB/Lab)
```bash
# Example with HackTheBox machine
python3 client.py 10.10.11.59 10.10.14.1

# Single module test
python3 client.py 10.10.11.59 10.10.14.1 -m nmap
```

### Expected Output Structure
```
results/
├── nmap_quick_*.txt
├── nmap_vuln_*.txt
├── nmap_smb_*.txt
├── nmap_summary_*.json
└── session_*.json

payloads/
├── reverse_shells.txt
├── listener_setup.sh
├── linux_x64_meter.elf
├── win_x64_meter.exe
└── persistence/

exploits/
├── dirtycow.c
├── dirtycow
├── kernel_exp.c
└── kernel_exp

logs/
└── khora_*.log
```

---

## Usage Examples

### 1. Network Reconnaissance
```bash
python3 client.py 192.168.1.100 10.10.14.1 -m nmap
```

### 2. Generate Payloads
```bash
python3 client.py 192.168.1.100 10.10.14.1 -m backdoor
```

### 3. Start C2 Server
```bash
python3 client.py 192.168.1.100 10.10.14.1 -m c2
```

### 4. Full Assessment
```bash
python3 client.py 192.168.1.100 10.10.14.1 --sequential
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'scapy'"
```bash
pip install scapy
```

### "nmap: command not found"
```bash
sudo apt install nmap
```

### "Permission denied" on compile
```bash
# Ensure gcc is installed
sudo apt install build-essential

# Or compile manually
gcc -o exploits/dirtycow exploits/dirtycow.c -pthread
```

### "OSError: [Errno 1] Operation not permitted"
```bash
# Some modules require root/admin
sudo python3 client.py ...
```

---

## Verification Checklist

- [ ] Python 3.8+ installed: `python3 --version`
- [ ] Virtual environment created: `which python3`
- [ ] Dependencies installed: `pip list | grep scapy`
- [ ] Nmap installed: `nmap --version`
- [ ] Netcat installed: `nc -h`
- [ ] GCC installed: `gcc --version`
- [ ] Khora loads: `python3 client.py --list`
- [ ] Can reach test target: `ping 192.168.1.100`

---

## Security Configuration

### Run Securely
```bash
# Use VPN for remote testing
# Create isolated virtual machine
# Document all testing activities
# Only test authorized targets
```

### Firewall Configuration (Linux)
```bash
# Allow outbound for C2
sudo ufw allow out 4444/tcp
sudo ufw allow out 8080/tcp
```

### Network Isolation
- Test on isolated lab network
- Use HTB VPN for HTB machines
- Never run on production networks
- Document target IPs and dates

---

## Next Steps

1. Review: `README.md` - Framework overview
2. Review: `SECURITY.md` - Security policies
3. Run: `python3 client.py --list` - See available modules
4. Test: `python3 client.py <target> <lhost>` - Practice run
5. Analyze: `results/` - Review generated reports

---

## Support

- **Framework Help**: `python3 client.py --help`
- **Module List**: `python3 client.py --list`
- **Issues**: Check `logs/khora_*.log`
- **Community**: Discord `2b53`

---

**Ready to start penetration testing with Khora!**
