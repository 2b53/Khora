#!/usr/bin/env python3
import os
import sys
import ast
import importlib.util
import inspect
import platform
import subprocess
import json
import shutil
from pathlib import Path
import concurrent.futures
from typing import Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_DIR = os.path.join(BASE_DIR, "modules")
RESULTS_DIR = os.path.join(BASE_DIR, "diagnostic_results")

# Colors (Windows-safe)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_colored(msg: str, color: str):
    print(f"{color}{msg}{Colors.END}")

# --------------------------------------------------
# WINDOWS-COMPATIBLE Environment Analysis
# --------------------------------------------------
def analyze_environment() -> Dict:
    """Complete forensic environment analysis - Windows/Linux/Mac"""
    is_windows = platform.system() == "Windows"
    env = {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "python": sys.version.split()[0],
        "user": os.getenv("USERNAME") if is_windows else os.getenv("USER", "unknown"),
        "uid": os.getuid() if not is_windows else os.getpid(),
        "is_root": False,
        "cwd": os.getcwd(),
        "net_interfaces": []
    }
    
    # Root/Admin detection
    try:
        if is_windows:
            result = subprocess.run(["net", "session"], capture_output=True, shell=True)
            env["is_root"] = result.returncode == 0
        else:
            env["is_root"] = os.geteuid() == 0
    except:
        pass
    
    # Network interfaces (cross-platform)
    try:
        if is_windows:
            result = subprocess.run(["netsh", "interface", "show", "interface"], 
                                  capture_output=True, text=True, shell=True)
            env["net_interfaces"] = [line.split()[-1] for line in result.stdout.splitlines() 
                                   if "Connected" in line and "Wi-Fi" not in line]
        else:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
            env["net_interfaces"] = [line.split(":")[1].strip() for line in result.stdout.splitlines() 
                                   if ":" in line and "lo" not in line]
    except:
        pass
    
    # HTB VPN detection (tun0/utun0/HackTheBox TAP)
    vpn_indicators = ["tun0", "utun0", "tap", "HackTheBox", "HTB"]
    env["htb_vpn"] = any(indicator in str(env["net_interfaces"]) for indicator in vpn_indicators)
    
    return env

# --------------------------------------------------
# Enhanced Dependency Analysis (Windows pip)
# --------------------------------------------------
def forensic_deps() -> Dict[str, Dict]:
    """Advanced dependency analysis with Windows pip commands"""
    critical_deps = {
        "scapy": {"module": "scapy.all", "purpose": "dns_spoof/sniffer"},
        "requests": {"module": "requests", "purpose": "RCE/privesc"},
        "pycryptodome": {"module": "Crypto", "purpose": "encryption"},
        "lxml": {"module": "lxml", "purpose": "XML parsing"},
        "cryptography": {"module": "cryptography", "purpose": "TLS/crypto"}
    }
    
    optional_deps = {
        "bleak": {"purpose": "BLE attacks (Windows)"},
        "impacket": {"purpose": "SMB/kerberos"},
        "pywin32": {"purpose": "Windows APIs"}
    }
    
    results = {}
    for name, info in {**critical_deps, **optional_deps}.items():
        try:
            __import__(info.get("module", name))
            results[name] = {"status": "OK", "purpose": info["purpose"]}
        except ImportError:
            pip_cmd = "pip install" if platform.system() != "Windows" else "pip install"
            results[name] = {
                "status": "MISSING" if name in critical_deps else "WARN",
                "purpose": info["purpose"],
                "fix": f"{pip_cmd} {name}"
            }
    
    return results

# --------------------------------------------------
# Auto-Fix System (CLI Args)
# --------------------------------------------------
def auto_fix_module(mod_name: str) -> bool:
    """Auto-fix broken module by adding run() template"""
    mod_path = os.path.join(MODULE_DIR, f"{mod_name}.py")
    if not os.path.exists(mod_path):
        print_colored(f"❌ Module {mod_name}.py not found", Colors.RED)
        return False
    
    # Check if already has run()
    try:
        with open(mod_path, "r") as f:
            content = f.read()
            if "def run(" in content:
                print_colored(f"✅ {mod_name}: run() already exists", Colors.GREEN)
                return True
    except:
        pass
    
    # Generate fix
    fix_template = generate_autofix(mod_name)
    
    # Backup original
    backup_path = f"{mod_path}.backup"
    shutil.copy2(mod_path, backup_path)
    
    # Append fix
    with open(mod_path, "a") as f:
        f.write("\n\n" + fix_template)
    
    print_colored(f"🔧 {mod_name}: Auto-fixed run() + backup created", Colors.GREEN)
    return True

def generate_autofix(mod_name: str) -> str:
    """Generate missing run() function template"""
    attack_type = mod_name.replace("_module", "").replace("_", " ").title()
    return f'''def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - {attack_type}"""
    print(f"[+] {{attack_type}}: {{target}} -> {{lhost}}:{{lport}}")
    print("[+] {mod_name}: Attack logic ready - customize here!")
    # TODO: Implement {attack_type.lower()} attack chain
'''

# --------------------------------------------------
# Module Forensic (Unchanged core logic)
# --------------------------------------------------
def forensic_module_analysis(mod_path: str, mod_name: str) -> Dict:
    """Complete forensic analysis of single module"""
    result = {
        "name": mod_name,
        "path": mod_path,
        "status": "OK",
        "issues": [],
        "features": [],
        "lines": 0,
        "imports": [],
        "run_signature": None
    }
    
    stat = os.stat(mod_path)
    result["size"] = stat.st_size
    result["modified"] = stat.st_mtime
    
    try:
        with open(mod_path, "r", encoding="utf-8") as f:
            source = f.read()
            tree = ast.parse(source)
            result["lines"] = len(source.splitlines())
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    result["imports"].extend([n.name for n in node.names])
                elif isinstance(node, ast.ImportFrom):
                    result["imports"].append(node.module)
                    
    except SyntaxError as e:
        result["status"] = "SYNTAX_ERROR"
        result["issues"].append(f"SyntaxError: {e}")
        return result
    
    try:
        spec = importlib.util.spec_from_file_location(mod_name, mod_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as e:
        result["status"] = "IMPORT_ERROR"
        result["issues"].append(f"ImportError: {e}")
        return result
    
    if not hasattr(module, "run"):
        result["status"] = "MISSING_RUN"
        result["issues"].append("Missing run() function")
    else:
        run_fn = module.run
        sig = inspect.signature(run_fn)
        result["run_signature"] = str(sig)
        params = list(sig.parameters.values())
        if len(params) >= 2:
            result["features"].append("Khora compatible")
    
    source_lower = source.lower()
    features = {
        "msfvenom": "backdoor", "hashcat": "cracker", 
        "scapy": "dns_spoof/sniffer", "requests": "RCE",
        "socket": "c2", "metasploit": "exploit"
    }
    
    for keyword, feature in features.items():
        if keyword in source_lower:
            result["features"].append(feature)
    
    return result

# --------------------------------------------------
# Windows-Compatible Client Test
# --------------------------------------------------
def test_client_integration(target: str = "10.10.11.59", lhost: str = "10.10.14.1"):
    """Test client.py module loading (Windows-safe)"""
    client_path = os.path.join(BASE_DIR, "client.py")
    if not os.path.exists(client_path):
        return {"status": "WARN", "message": "client.py not found"}
    
    print_colored("\n🚀 Testing client.py integration...", Colors.BLUE)
    try:
        cmd = ["python3", client_path, target, lhost, "-m", "nmap_module"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return {"status": "OK", "output": result.stdout[:200]}
        else:
            return {"status": "ERROR", "error": result.stderr[:200]}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

# --------------------------------------------------
# MAIN with CLI Args
# --------------------------------------------------
def main():
    # Parse args
    args = sys.argv[1:]
    autofix_all = "--autofix-all" in args
    autofix_single = [arg.replace("--autofix ", "") for arg in args if arg.startswith("--autofix ")]
    
    if autofix_all:
        print_colored("🔧 AUTO-FIX MODE: Fixing ALL modules...", Colors.YELLOW)
    elif autofix_single:
        print_colored(f"🔧 AUTO-FIX MODE: Fixing {autofix_single[0]}...", Colors.YELLOW)
    
    # Setup
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    print_colored("\n" + "="*70, Colors.BOLD)
    print_colored("🔍 KHORA FRAMEWORK – WINDOWS-COMPATIBLE ULTIMATE FIX", Colors.BOLD)
    print_colored("="*70, Colors.BOLD)
    
    # 1. Environment (NOW WINDOWS-SAFE!)
    env = analyze_environment()
    print_colored("\n🖥️  ENVIRONMENT FORENSICS", Colors.GREEN)
    print(f"    OS: {env['os']} {env['release']} ({env['arch']})")
    print(f"    Python: {env['python']}")
    print(f"    User: {env['user']} ({'ADMIN' if env['is_root'] else 'User'})")
    print(f"    HTB VPN: {'✅ Detected' if env['htb_vpn'] else '❌ No VPN'}")
    print(f"    Interfaces: {', '.join(env['net_interfaces'][:3])}")
    
    # 2. Auto-fix phase
    if autofix_all:
        module_files = [f for f in os.listdir(MODULE_DIR) if f.endswith(".py") and not f.startswith("__")]
        fixed_count = 0
        for mod in module_files:
            if auto_fix_module(mod[:-3]):
                fixed_count += 1
        print_colored(f"\n✅ AUTO-FIX COMPLETE: {fixed_count}/{len(module_files)} modules fixed!", Colors.GREEN)
    
    elif autofix_single:
        auto_fix_module(autofix_single[0])
    
    # 3. Dependencies
    print_colored("\n📦 DEPENDENCY FORENSICS", Colors.GREEN)
    deps = forensic_deps()
    missing_critical = [k for k,v in deps.items() if v["status"] == "MISSING"]
    if missing_critical:
        print_colored(f"    🚨 CRITICAL: {len(missing_critical)} deps missing:", Colors.RED)
        for dep in missing_critical:
            print(f"        pip install {dep}")
    
    # 4. Module analysis (parallel)
    print_colored("\n🔬 MODULE FORENSIC ANALYSIS", Colors.GREEN)
    module_files = [f for f in os.listdir(MODULE_DIR) if f.endswith(".py") and not f.startswith("__")]
    
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_mod = {
            executor.submit(forensic_module_analysis, os.path.join(MODULE_DIR, mod), mod[:-3]): mod 
            for mod in module_files
        }
        for future in concurrent.futures.as_completed(future_to_mod):
            mod_name = future_to_mod[future]
            try:
                results[mod_name[:-3]] = future.result()
                mod_result = results[mod_name[:-3]]
                
                print(f"\n    📁 {mod_name[:-3]}")
                status_color = {
                    "OK": Colors.GREEN, "SYNTAX_ERROR": Colors.RED,
                    "IMPORT_ERROR": Colors.RED, "MISSING_RUN": Colors.YELLOW
                }.get(mod_result["status"], Colors.BLUE)
                
                print_colored(f"       Status: {mod_result['status']}", status_color)
                print(f"       Size: {mod_result['size']}B | Lines: {mod_result['lines']}")
                
                if mod_result["issues"]:
                    print_colored(f"       🚨 Issues ({len(mod_result['issues'])}):", Colors.RED)
                    for issue in mod_result["issues"][:2]:  # First 2 issues
                        print(f"           • {issue}")
                
            except Exception as e:
                print(f"    [!] Analysis failed: {e}")
    
    # 5. Summary
    print_colored("\n📊 EXECUTIVE SUMMARY", Colors.BOLD)
    ok_modules = [m for m,r in results.items() if r["status"] == "OK"]
    print(f"    ✅ Healthy: {len(ok_modules)}/{len(results)} modules")
    
    # 6. Client test
    client_test = test_client_integration()
    print_colored("\n🚀 CLIENT INTEGRATION TEST", Colors.GREEN)
    status_color = Colors.GREEN if client_test["status"] == "OK" else Colors.YELLOW
    print_colored(f"    {client_test['status']}", status_color)
    
    # 7. Report
    report = {"environment": env, "dependencies": deps, "modules": results, "client_test": client_test}
    report_path = os.path.join(RESULTS_DIR, "forensic_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print_colored(f"\n💾 Report saved: {report_path}", Colors.BLUE)
    
    score = (len(ok_modules) / len(results)) * 100 if results else 0
    print_colored(f"\n🎯 KHORA READINESS: {score:.1f}%", Colors.BOLD)
    if score >= 90:
        print_colored("🚀 FRAMEWORK BATTLE-READY! python3 client.py 10.10.11.59 10.10.14.1", Colors.GREEN)

if __name__ == "__main__":
    main()