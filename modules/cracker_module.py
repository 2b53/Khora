"""
Cracker Module - Hash Dictionary Attack & Password Cracking
Hashcat Integration, GPU Support, Multi-Wordlist, Performance Optimization
"""

import subprocess
import os
import sys
import logging
import json
import time
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("Khora.Cracker")

class CrackerModule:
    def __init__(self, target, lhost, lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.results = {
            'cracked': [],
            'failed': [],
            'statistics': {}
        }
        
        Path("results").mkdir(exist_ok=True)
        Path("wordlists").mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
    
    def detect_gpu(self):
        """Detect available GPU for acceleration"""
        print(f"\n[*] Detecting GPU support...")
        
        try:
            # Check NVIDIA
            result = subprocess.run(["nvidia-smi"], capture_output=True, timeout=5)
            if result.returncode == 0:
                print("  [✓] NVIDIA GPU detected")
                logger.info("NVIDIA GPU available")
                return "CUDAExecutionProvider"
        except:
            pass
        
        # Check AMD
        try:
            result = subprocess.run(["rocm-smi"], capture_output=True, timeout=5)
            if result.returncode == 0:
                print("  [✓] AMD GPU detected")
                logger.info("AMD GPU available")
                return "HIPExecutionProvider"
        except:
            pass
        
        print("  [!] No GPU detected - CPU mode")
        logger.info("CPU mode only")
        return "CPU"
    
    def identify_hash_type(self, hash_value):
        """Identify hash type from format"""
        hash_value = hash_value.strip()
        
        # Windows NTLM - 32 hex chars
        if len(hash_value) == 32 and all(c in "0123456789abcdefABCDEF" for c in hash_value):
            return ("1000", "NTLM")
        
        # SHA256 - 64 hex chars
        if len(hash_value) == 64 and all(c in "0123456789abcdefABCDEF" for c in hash_value):
            return ("1400", "SHA256")
        
        # SHA1 - 40 hex chars
        if len(hash_value) == 40 and all(c in "0123456789abcdefABCDEF" for c in hash_value):
            return ("100", "SHA1")
        
        # Kerberos - starts with $krb5tgs$23$
        if hash_value.startswith("$krb5tgs$23$"):
            return ("13100", "Kerberos 5 TGS-REP")
        
        # MD5 - 32 hex chars with $ prefix sometimes
        if hash_value.startswith("$1$"):
            return ("500", "MD5 crypt")
        
        return (None, "Unknown")
    
    def validate_hashcat(self):
        """Check if hashcat is installed"""
        try:
            result = subprocess.run(["hashcat", "--version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.decode().strip()
                print(f"  [✓] hashcat found: {version}")
                logger.info(f"hashcat: {version}")
                return True
        except FileNotFoundError:
            print("  [!] hashcat not installed")
            print("     Linux: sudo apt install hashcat")
            print("     macOS: brew install hashcat")
            logger.error("hashcat not found")
            return False
    
    def crack_hashes(self, hash_file, wordlist=None):
        """Crack hashes using hashcat with multiple wordlists"""
        
        if not os.path.exists(hash_file):
            print(f"[!] Hash file not found: {hash_file}")
            return False
        
        if not self.validate_hashcat():
            return False
        
        # Default wordlist
        if not wordlist:
            wordlist = "wordlists/rockyou.txt"
        
        if not os.path.exists(wordlist):
            print(f"[!] Wordlist not found: {wordlist}")
            print("[!] Download: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
            return False
        
        print(f"\n[*] Reading hashes from: {hash_file}")
        
        # Parse hashes
        hashes_by_type = {}
        with open(hash_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                hash_mode, hash_type = self.identify_hash_type(line)
                if hash_mode:
                    if hash_mode not in hashes_by_type:
                        hashes_by_type[hash_mode] = {'type': hash_type, 'hashes': []}
                    hashes_by_type[hash_mode]['hashes'].append(line)
                else:
                    print(f"  [?] Unknown hash: {line[:30]}")
        
        print(f"\n[*] Identified hash types:")
        for hash_mode, data in hashes_by_type.items():
            print(f"  [{hash_mode}] {data['type']}: {len(data['hashes'])} hashes")
        
        # Crack each type
        gpu_mode = self.detect_gpu()
        
        for hash_mode, data in hashes_by_type.items():
            print(f"\n[*] Cracking {data['type']} hashes...")
            
            # Create temp hash file
            temp_hash_file = f"results/temp_hashes_{hash_mode}.txt"
            with open(temp_hash_file, 'w') as f:
                f.write('\n'.join(data['hashes']))
            
            output_file = f"results/cracked_{data['type'].replace(' ', '_')}_{datetime.now().strftime('%H%M%S')}.txt"
            
            # Build hashcat command
            cmd = [
                "hashcat",
                "-m", hash_mode,
                "-a", "0",
                temp_hash_file,
                wordlist,
                "-o", output_file,
                "--potfile-disable",
                "--quiet"
            ]
            
            # Add GPU acceleration if available
            if gpu_mode != "CPU":
                cmd.append("-d")
                cmd.append("1")  # GPU device
            
            start_time = time.time()
            
            try:
                print(f"  [+] Running hashcat (mode {hash_mode})...")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                
                elapsed = time.time() - start_time
                
                if os.path.exists(output_file):
                    with open(output_file) as f:
                        cracked_lines = f.readlines()
                    
                    print(f"  [✓] Cracked: {len(cracked_lines)} hashes in {elapsed:.1f}s")
                    self.results['cracked'].append({
                        'type': data['type'],
                        'count': len(cracked_lines),
                        'file': output_file,
                        'time': f"{elapsed:.1f}s"
                    })
                    
                    # Show sample
                    if cracked_lines:
                        print(f"      Example: {cracked_lines[0][:60]}")
                else:
                    print(f"  [!] No cracks found")
                    self.results['failed'].append({
                        'type': data['type'],
                        'reason': 'no_cracks'
                    })
                
                # Cleanup temp file
                os.remove(temp_hash_file)
                
            except FileNotFoundError:
                logger.error("hashcat not found")
            except subprocess.TimeoutExpired:
                print(f"  [!] Timeout after 600s")
                self.results['failed'].append({
                    'type': data['type'],
                    'reason': 'timeout'
                })
            except Exception as e:
                logger.error(f"Cracking error: {e}")
                print(f"  [!] Error: {e}")
        
        return True
    
    def benchmark_wordlist(self):
        """Benchmark cracking speed"""
        print(f"\n[*] Hashcat Benchmark")
        
        try:
            result = subprocess.run(
                ["hashcat", "-b", "-m", "1000"],
                capture_output=True, text=True, timeout=60
            )
            
            # Extract benchmark info
            output = result.stdout
            if "Speed" in output:
                for line in output.split('\n'):
                    if "Speed" in line or "Estimated" in line:
                        print(f"  {line.strip()}")
        except Exception as e:
            logger.error(f"Benchmark failed: {e}")
    
    def save_results(self):
        """Save cracking results and statistics"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            results_file = Path("results") / f"cracker_results_{timestamp}.json"
            
            self.results['statistics'] = {
                'total_cracked': sum(r.get('count', 0) for r in self.results['cracked']),
                'total_failed': len(self.results['failed']),
                'timestamp': datetime.now().isoformat()
            }
            
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            logger.info(f"Results saved: {results_file}")
            
        except Exception as e:
            logger.error(f"Save results failed: {e}")
    
    def run(self, hash_file="hashes.txt", wordlist=None):
        """Execute hash cracking"""
        print(f"\n{'='*70}")
        print("CRACKER MODULE - HASH DICTIONARY ATTACK".center(70))
        print('='*70 + "\n")
        
        logger.info(f"Cracker module started for {self.target}")
        
        # Crack hashes
        self.crack_hashes(hash_file, wordlist)
        
        # Benchmark
        self.benchmark_wordlist()
        
        # Save results
        self.save_results()
        
        print(f"\n{'='*70}")
        print(f"Hash Cracking Complete - Check results/".center(70))
        print('='*70 + "\n")

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - Cracker Module"""
    
    print(f"[*] Hash Cracking Module")
    print(f"[*] Target: {target}\n")
    
    cracker = CrackerModule(target, lhost, lport)
    
    # Try to crack hashes from file
    hash_file = "hashes.txt"
    if os.path.exists(hash_file):
        cracker.run(hash_file)
    else:
        print(f"[!] Create hashes.txt with password hashes in format:")
        print("    NTLM (32 hex chars): a1f8c3d9e2b4f5a6...")
        print("    SHA256 (64 hex chars): 5feceb66ffc86f38d952...")
        print("    Kerberos: $krb5tgs$23$...")