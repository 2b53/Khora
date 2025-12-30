import subprocess
import xml.etree.ElementTree as ET
import os
from pathlib import Path

def run_scan(target):
    Path("results").mkdir(exist_ok=True)
    
    
    subprocess.run(["nmap", "-sS", "-sV", "-oX", "results/nmap_tcp.xml", target], check=True)
    
    
    subprocess.run(["nmap", "-sU", "--top-ports", "100", "-oX", "results/nmap_udp.xml", target], check=True)
    
    
    subprocess.run(["nmap", "--script", "vuln", "-oX", "results/nmap_vuln.xml", target], check=True)
    
    
    subprocess.run(["nmap", "--script", "http-struts-validator", "-p80,8080", "-oX", "results/nmap_struts.xml", target], check=True)
    
    parse_xml_results(target)
    print(f"[+] Nmap scans complete: results/nmap_*.txt")

def parse_xml_results(target):
    for xml_file in Path("results").glob("nmap_*.xml"):
        tree = ET.parse(xml_file)
        with open(f"results/{xml_file.stem}.txt", "w") as f:
            for host in tree.findall(".//host"):
                ip = host.find("address").get("addr")
                f.write(f"Host: {ip}\n")
                for port in host.findall(".//port"):
                    portid = port.find("portid").get("value")
                    state = port.find("state").get("state")
                    service = port.find(".//service").get("name", "unknown")
                    f.write(f"  {portid}/tcp {state} {service}\n")