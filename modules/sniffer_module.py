"""
Network Sniffer Module - Packet Analysis and Credential Detection
Protocol Filtering, Clear-Text Detection, Statistics Tracking
"""

from scapy.all import *
import sys
import logging
import json
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger("Khora.Sniffer")

class NetworkSniffer:
    def __init__(self, interface, target_ip=None):
        self.interface = interface
        self.target_ip = target_ip
        self.packets_captured = 0
        self.credentials_found = []
        self.protocols = defaultdict(int)
        self.clear_text_detected = []
        self.stats = {
            'start_time': datetime.now().isoformat(),
            'interface': interface,
            'target': target_ip
        }
        
        Path("logs").mkdir(exist_ok=True)
        Path("results").mkdir(exist_ok=True)
    
    def detect_credentials(self, payload):
        """Detect common credential patterns in clear-text"""
        credentials = []
        
        # HTTP Basic Auth
        if b'Authorization: Basic' in payload:
            match = re.search(b'Authorization: Basic ([A-Za-z0-9+/=]+)', payload)
            if match:
                b64 = match.group(1).decode()
                try:
                    decoded = bytes.fromhex(b64).decode('base64') if isinstance(b64, str) else b64
                    credentials.append(('HTTP-BasicAuth', decoded))
                except:
                    pass
        
        # FTP Commands
        if b'USER' in payload or b'PASS' in payload:
            lines = payload.split(b'\n')
            for line in lines:
                if b'USER' in line or b'PASS' in line:
                    credentials.append(('FTP', line.decode(errors='ignore')))
        
        # SMTP Auth
        if b'AUTH LOGIN' in payload or b'MAIL FROM' in payload:
            credentials.append(('SMTP', payload[:50].decode(errors='ignore')))
        
        # Telnet/SSH credentials
        if b'login:' in payload or b'password:' in payload or b'ssh' in payload.lower():
            credentials.append(('Telnet/SSH', 'Potential login session detected'))
        
        return credentials
    
    def analyze_packet(self, pkt):
        """Analyze packet for protocols and credentials"""
        try:
            self.packets_captured += 1
            
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ttl = pkt[IP].ttl
                
                # Check if matches target
                if self.target_ip and self.target_ip not in [src_ip, dst_ip]:
                    return
                
                proto_str = ""
                payload = b""
                
                # TCP Analysis
                if pkt.haslayer(TCP):
                    tcp_sport = pkt[TCP].sport
                    tcp_dport = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    proto_str = f"TCP {src_ip}:{tcp_sport} -> {dst_ip}:{tcp_dport}"
                    self.protocols['TCP'] += 1
                    
                    # Identify services
                    if tcp_dport in [21, 2121]:
                        self.protocols['FTP'] += 1
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load
                    elif tcp_dport in [23]:
                        self.protocols['Telnet'] += 1
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load
                    elif tcp_dport in [80, 3000, 5000, 8080, 8000]:
                        self.protocols['HTTP'] += 1
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load
                    elif tcp_dport in [25, 587, 465]:
                        self.protocols['SMTP'] += 1
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load
                    elif tcp_dport in [22]:
                        self.protocols['SSH'] += 1
                    
                # UDP Analysis
                elif pkt.haslayer(UDP):
                    udp_sport = pkt[UDP].sport
                    udp_dport = pkt[UDP].dport
                    proto_str = f"UDP {src_ip}:{udp_sport} -> {dst_ip}:{udp_dport}"
                    self.protocols['UDP'] += 1
                    
                    if udp_dport in [53]:
                        self.protocols['DNS'] += 1
                    elif udp_dport in [5353]:
                        self.protocols['mDNS'] += 1
                    elif udp_dport in [137, 138, 139]:
                        self.protocols['NetBIOS'] += 1
                
                # Detect credentials if payload found
                if payload:
                    creds = self.detect_credentials(payload)
                    if creds:
                        for cred_type, cred_data in creds:
                            self.credentials_found.append({
                                'timestamp': datetime.now().isoformat(),
                                'source': src_ip,
                                'destination': dst_ip,
                                'type': cred_type,
                                'data': cred_data[:50]
                            })
                            print(f"  [!] CREDENTIAL: {cred_type} from {src_ip}")
                            self.clear_text_detected.append(cred_type)
                
                if proto_str:
                    print(f"  [+] {proto_str}")
                    logger.debug(f"Packet: {proto_str}")
                    
        except Exception as e:
            logger.error(f"Packet analysis error: {e}")
    
    def save_results(self):
        """Save sniffer results to file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            results_file = Path("results") / f"sniffer_results_{timestamp}.json"
            
            self.stats['end_time'] = datetime.now().isoformat()
            self.stats['packets_captured'] = self.packets_captured
            self.stats['protocols_detected'] = dict(self.protocols)
            self.stats['clear_text_protocols'] = list(set(self.clear_text_detected))
            self.stats['credentials_found'] = len(self.credentials_found)
            
            with open(results_file, 'w') as f:
                json.dump({
                    'statistics': self.stats,
                    'credentials_sample': self.credentials_found[:10],
                }, f, indent=2)
            
            logger.info(f"Results saved to {results_file}")
            
        except Exception as e:
            logger.error(f"Save results error: {e}")
    
    def run(self, packet_count=None):
        """Start packet sniffing"""
        print(f"\n{'='*70}")
        print("NETWORK SNIFFER MODULE".center(70))
        print('='*70)
        print(f"Interface: {self.interface}")
        if self.target_ip:
            print(f"Target IP: {self.target_ip}")
        print(f"Listening for packets...\n")
        
        logger.info(f"Sniffer started on {self.interface}")
        
        try:
            sniff(iface=self.interface, prn=self.analyze_packet, 
                  filter="tcp or udp", store=0, count=packet_count)
        except KeyboardInterrupt:
            print(f"\n\n[+] Sniffer stopped by user")
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            print(f"[!] Error: {e}")
            print("[!] Run as root/admin for packet capture")
        finally:
            self.save_results()
            print(f"{'='*70}")
            print(f"Captured {self.packets_captured} packets | {len(self.credentials_found)} credentials".center(70))
            print('='*70 + "\n")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Network Sniffer Module"""
    
    # Auto-detect interface
    interface = "eth0"
    try:
        for iface in ["tun0", "tap0", "wlan0", "eth0", "ens0"]:
            try:
                get_if_hwaddr(iface)
                interface = iface
                break
            except:
                continue
    except:
        pass
    
    print(f"[*] Network Sniffer - Target: {target}")
    print(f"[*] Interface: {interface}\n")
    
    logger.info(f"Sniffer module: {target}")
    
    sniffer = NetworkSniffer(interface, target_ip=target)
    sniffer.run()