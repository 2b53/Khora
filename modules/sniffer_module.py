from scapy.all import *
import sys

def packet_handler(pkt):
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        print(f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")

def run_sniffer(interface="tun0"):
    print(f"[+] Packet sniffer: {interface}")
    print("[+] Press Ctrl+C to stop")
    sniff(iface=interface, prn=packet_handler, filter="tcp or udp", store=0)

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Network Sniffer"""
    print(f"[+] Sniffer module: Monitoring {target} traffic")
    
    interface = "tun0" 
    if "linux" not in sys.platform:
        interface = "eth0"
    
    try:
        run_sniffer(interface)
    except KeyboardInterrupt:
        print("\n[+] Sniffer stopped")
    except Exception as e:
        print(f"[!] Sniffer error: {e} (run as root)")