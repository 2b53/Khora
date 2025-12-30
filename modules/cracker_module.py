import subprocess
import os

def crack_hashes(hash_file):
    os.makedirs("results", exist_ok=True)
    
    
    subprocess.run([
        "hashcat", "-m", "1000", "-a", "0", 
        hash_file, "wordlists/rockyou.txt", 
        "-o", "results/cracked_ntlm.txt"
    ])
    
    
    subprocess.run([
        "hashcat", "-m", "1400", "-a", "0", 
        hash_file, "wordlists/rockyou.txt", 
        "-o", "results/cracked_sha256.txt"
    ])
    
    
    subprocess.run([
        "hashcat", "-m", "13100", "-a", "0", 
        hash_file, "wordlists/rockyou.txt", 
        "-o", "results/cracked_kerberos.txt"
    ])
    
    print("[+] Cracking complete: results/cracked_*.txt")

def run_cracker(hash_file="hashes.txt"):
    crack_hashes(hash_file)