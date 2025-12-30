from scapy.all import *

class SnifferModule:
    def __init__(self, interface):
        self.interface = interface
    
    def wifi_sniffer(self):
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Beacon].info.decode()
                bssid = pkt[Dot11].addr3
                print(f"SSID: {ssid} BSSID: {bssid}")
            elif pkt.haslayer(Dot11Auth):
                print(f"Auth attempt: {pkt[Dot11].addr2} -> {pkt[Dot11].addr3}")
        
        sniff(iface=self.interface, prn=packet_handler, store=0)
    
    def ble_sniffer(self):
        sniff(iface="hci0", filter="btle", prn=lambda x: print(x.summary()))