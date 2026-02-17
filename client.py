#!/usr/bin/env python3
"""
Khora Security Testing Framework v2.1
Modular penetration testing & attack simulation framework

Developed by: 2b53
Author: 2b53
Framework Version: 2.1
"""

import sys
import os
import logging
import importlib.util
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
import json

# Setup
MODULE_DIR = Path("modules")
RESULTS_DIR = Path("results")
LOG_DIR = Path("logs")
EXPLOITS_DIR = Path("exploits")

# Create directories
RESULTS_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
EXPLOITS_DIR.mkdir(exist_ok=True)

# Configure logging
LOG_FILE = LOG_DIR / f"khora_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Khora")

# Banner
BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║   KHORA Security Testing Framework v2.1                  ║
║   Professional Penetration Testing Suite                 ║
║   By 2b53                                                ║
║   [AUTHORIZED TESTING ONLY]                              ║
╚══════════════════════════════════════════════════════════╝
"""

MODULE_INFO = {
    'nmap': {'desc': 'Network Scanning & Vulnerability Detection', 'type': 'Recon', 'critical': False},
    'rce': {'desc': 'Remote Code Execution Exploits', 'type': 'Exploit', 'critical': True},
    'backdoor': {'desc': 'Reverse Shell & Payload Generation', 'type': 'Payload', 'critical': True},
    'blueborne': {'desc': 'Bluetooth Exploitation (CVE-2017-0785)', 'type': 'Bluetooth', 'critical': False},
    'cracker': {'desc': 'Hash Cracking (NTLM/SHA256/Kerberos)', 'type': 'Cracking', 'critical': False},
    'jailbreak': {'desc': 'Container Escape & Privilege Escalation', 'type': 'Privesc', 'critical': True},
    'c2': {'desc': 'Command & Control Server', 'type': 'C2', 'critical': True},
    'dns_spoof': {'desc': 'DNS Poisoning & Spoofing', 'type': 'Network', 'critical': False},
    'sniffer': {'desc': 'Packet Capture & Analysis', 'type': 'Recon', 'critical': False},
    'eternalblue': {'desc': 'MS17-010 SMB Exploitation', 'type': 'SMB', 'critical': True}
}

def print_banner():
    print(BANNER)
    print(f"[*] Log file: {LOG_FILE}\n")

def load_module(filename):
    """Load Python module dynamically"""
    try:
        spec = importlib.util.spec_from_file_location(
            filename.replace('.py',''), 
            MODULE_DIR / filename
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.error(f"Failed to load module {filename}: {e}")
        return None

def execute_module(module_name, target, lhost, lport=4444):
    """Execute a single module with error handling"""
    try:
        logger.info(f"Starting module: {module_name}")
        mod = load_module(f"{module_name}_module.py")
        
        if mod is None:
            logger.warning(f"Module {module_name} could not be loaded")
            return False
        
        # Check for run function
        run_func = getattr(mod, 'run', None)
        if run_func is None:
            logger.error(f"Module {module_name} missing 'run' function")
            return False
        
        # Execute with parameters
        run_func(target, lhost, lport)
        logger.info(f"Module {module_name} completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Module {module_name} execution failed: {e}", exc_info=True)
        return False

def list_modules():
    """Display available modules"""
    print("\n" + "="*70)
    print("AVAILABLE MODULES".center(70))
    print("="*70)
    for name, info in sorted(MODULE_INFO.items()):
        critical = "[CRITICAL]" if info['critical'] else ""
        print(f"\n  [{info['type']:10}] {name:15} {critical}")
        print(f"      └─ {info['desc']}")
    print("\n" + "="*70 + "\n")

def create_session_report(target, lhost, lport, modules_run, success_count, start_time, end_time):
    """Create JSON report of testing session"""
    report = {
        "framework": "Khora",
        "version": "2.1",
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "target": target,
        "lhost": lhost,
        "lport": lport,
        "modules_executed": modules_run,
        "modules_successful": success_count,
        "success_rate": f"{(success_count/len(modules_run)*100):.1f}%",
        "log_file": str(LOG_FILE),
        "results_directory": str(RESULTS_DIR),
        "exploits_directory": str(EXPLOITS_DIR)
    }
    
    report_file = RESULTS_DIR / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Session report: {report_file}")
    return report_file

def validate_ip(ip_string):
    """Validate IP address format"""
    try:
        import ipaddress
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Khora Security Testing Framework v2.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Full assessment chain
  python3 client.py 192.168.1.100 10.10.14.1
  
  # Single module
  python3 client.py 192.168.1.100 10.10.14.1 -m backdoor
  
  # Custom port and parallel workers
  python3 client.py 192.168.1.100 10.10.14.1 -p 8888 --workers 3
  
  # Sequential execution with verbose output
  python3 client.py 192.168.1.100 10.10.14.1 --sequential -v
  
  # List available modules
  python3 client.py --list
        """
    )
    
    parser.add_argument("target", nargs='?', help="Target IP address")
    parser.add_argument("lhost", nargs='?', help="LHOST (listener address)")
    parser.add_argument("-m", "--module", help="Execute specific module")
    parser.add_argument("-p", "--port", type=int, default=4444, help="LPORT (default: 4444)")
    parser.add_argument("--list", action="store_true", help="List available modules")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--sequential", action="store_true", help="Run modules sequentially")
    parser.add_argument("--workers", type=int, default=5, help="Max parallel workers (default: 5)")
    
    args = parser.parse_args()
    
    # Handle --list
    if args.list:
        list_modules()
        return
    
    # Validate required arguments
    if not args.target or not args.lhost:
        parser.print_help()
        return
    
    # Validate IP format
    if not validate_ip(args.target) or not validate_ip(args.lhost):
        logger.error("Invalid IP address format")
        return
    
    logger.info(f"Target: {args.target} | LHOST: {args.lhost}:{args.port}")
    
    modules = list(MODULE_INFO.keys())
    start_time = datetime.now()
    
    if args.module:
        # Single module execution
        if args.module not in modules:
            logger.error(f"Unknown module: {args.module}")
            return
        
        logger.info(f"Running module: {args.module}")
        success = execute_module(args.module, args.target, args.lhost, args.port)
        modules_run = [args.module]
        success_count = 1 if success else 0
    else:
        # Full chain execution
        logger.info("Running full security assessment...")
        modules_run = []
        success_count = 0
        
        if args.sequential:
            for module_name in modules:
                if execute_module(module_name, args.target, args.lhost, args.port):
                    success_count += 1
                modules_run.append(module_name)
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(execute_module, mod, args.target, args.lhost, args.port): mod 
                    for mod in modules
                }
                
                for future in as_completed(futures):
                    module_name = futures[future]
                    try:
                        if future.result():
                            success_count += 1
                    except Exception as e:
                        logger.error(f"Exception in {module_name}: {e}")
                    modules_run.append(module_name)
    
    end_time = datetime.now()
    
    # Generate report
    report_file = create_session_report(
        args.target, args.lhost, args.port, 
        modules_run, success_count, start_time, end_time
    )
    
    # Print summary
    print("\n" + "="*70)
    print("EXECUTION SUMMARY".center(70))
    print("="*70)
    print(f"Target:           {args.target}")
    print(f"LHOST:            {args.lhost}:{args.port}")
    print(f"Modules Executed: {len(modules_run)}/{len(modules)}")
    print(f"Successful:       {success_count}")
    print(f"Duration:         {(end_time - start_time).total_seconds():.1f}s")
    print(f"Results:          {RESULTS_DIR}/")
    print(f"Exploits:         {EXPLOITS_DIR}/")
    print(f"Report:           {report_file}")
    print("="*70 + "\n")
    
    logger.info(f"Assessment complete")

if __name__ == "__main__":
    main()