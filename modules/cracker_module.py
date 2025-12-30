import subprocess
import os
import sys

def crack_hashes(hash_file):
    """Crack NTLM, SHA256, Kerberos hashes with rockyou.txt"""
    os.makedirs("results", exist_ok=True)
    
    hash_modes = [
        ("1000", "NTLM", "results/cracked_ntlm.txt"),
        ("1400", "SHA256", "results/cracked_sha256.txt"), 
        ("13100", "Kerberos 5 TGS-REP etype 23", "results/cracked_kerberos.txt")
    ]
    
    for mode, hash_type, output_file in hash_modes:
        try:
            print(f"[+] Cracking {hash_type} (-m {mode})...")
            result = subprocess.run([
                "hashcat", "-m", mode, "-a", "0",
                hash_file, "wordlists/rockyou.txt",
                "-o", output_file, "--quiet"
            ], capture_output=True, text=True, timeout=300)  # 5min timeout per mode
            
            if result.returncode == 0:
                print(f"[+] {hash_type} complete: {output_file}")
            else:
                print(f"[!] {hash_type} failed: {result.stderr[:200]}...")
                
        except FileNotFoundError:
            print("[!] hashcat not found - install with: sudo apt install hashcat")
        except subprocess.TimeoutExpired:
            print(f"[!] {hash_type} timeout - killed after 5min")
        except Exception as e:
            print(f"[!] {hash_type} error: {e}")
    
    # Show cracked results
    for result_file in ["results/cracked_ntlm.txt", "results/cracked_sha256.txt", "results/cracked_kerberos.txt"]:
        if os.path.exists(result_file):
            with open(result_file) as f:
                cracked = f.read().strip()
                if cracked:
                    print(f"\n[+] {result_file}: {cracked}")
                else:
                    print(f"[ ] {result_file}: No cracks")

def run(target, lhost, lport=4444, hash_file="hashes.txt"):
    """Khora Framework entrypoint - Hash Cracking"""
    print(f"[+] Cracker module: {target} -> hashcat rockyou.txt")
    
    if not os.path.exists(hash_file):
        print(f"[!] Hash file not found: {hash_file}")
        print("[ ] Create hashes.txt with: ntlm:hash | sha256:hash | $krb5tgs$23$...")
        return
    
    if not os.path.exists("wordlists/rockyou.txt"):
        print("[!] rockyou.txt not found - download: wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
        return
    
    print(f"[+] Target hashes: {hash_file}")
    crack_hashes(hash_file)
    print("[+] Cracking complete: results/cracked_*.txt")