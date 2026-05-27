#!/usr/bin/env python3
"""
Khora Security Testing Framework v2.1
Modular penetration testing and assessment framework.
"""

import argparse
import importlib.util
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from exploit_chains import ATTACK_PROFILES, list_attack_profiles, load_chain_profile
from sessions import SessionManager

MODULE_DIR = Path("modules")
RESULTS_DIR = Path("results")
LOG_DIR = Path("logs")
EXPLOITS_DIR = Path("exploits")

RESULTS_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
EXPLOITS_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / f"khora_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("Khora")

BANNER = r"""
+--------------------------------------------------------------------+
| KHORA Framework v2.1                                               |
| Modular Assessment Client                                          |
| Operator: 2b53                                                     |
| Authorized Security Testing Only                                   |
+--------------------------------------------------------------------+
"""

MODULE_INFO = {
    "nmap": {"desc": "Network scanning and service enumeration", "type": "Recon", "critical": False},
    "nuclei": {"desc": "Template-based vulnerability and misconfiguration assessment", "type": "Web", "critical": False},
    "rce": {"desc": "Remote code execution checks", "type": "Exploit", "critical": True},
    "backdoor": {"desc": "Payload and reverse shell artifact generation", "type": "Payload", "critical": True},
    "blueborne": {"desc": "Bluetooth exposure assessment (CVE-2017-0785)", "type": "Bluetooth", "critical": False},
    "cracker": {"desc": "Offline credential and hash analysis", "type": "Cracking", "critical": False},
    "jailbreak": {"desc": "Container escape and privilege escalation checks", "type": "Privesc", "critical": True},
    "c2": {"desc": "Session transport and control service", "type": "Control", "critical": True},
    "dns_spoof": {"desc": "DNS spoofing and poisoning lab module", "type": "Network", "critical": False},
    "sniffer": {"desc": "Packet capture and traffic inspection", "type": "Recon", "critical": False},
    "eternalblue": {"desc": "SMB exposure validation for MS17-010", "type": "SMB", "critical": True},
    "dirtycow": {"desc": "Local privilege escalation check for Dirty COW", "type": "Privesc", "critical": False},
}

MODULE_FILENAMES = {
    "rce": "RCE_module.py",
}


def print_banner():
    print(BANNER)
    print(f"[*] Log file: {LOG_FILE}\n")


def resolve_module_path(module_name):
    """Resolve a module file path, including legacy filename casing."""
    filename = MODULE_FILENAMES.get(module_name, f"{module_name}_module.py")
    return MODULE_DIR / filename


def load_module(module_name):
    """Load a module from disk."""
    try:
        module_path = resolve_module_path(module_name)
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Unable to create import spec for {module_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as exc:
        logger.error(f"Failed to load module {module_name}: {exc}")
        return None


def execute_module(module_name, target, lhost, lport=4444):
    """Execute a single module with error handling."""
    try:
        logger.info(f"Starting module: {module_name}")
        module = load_module(module_name)

        if module is None:
            logger.warning(f"Module {module_name} could not be loaded")
            return False

        run_func = getattr(module, "run", None)
        if run_func is None:
            logger.error(f"Module {module_name} missing 'run' function")
            return False

        run_func(target, lhost, lport)
        logger.info(f"Module {module_name} completed successfully")
        return True
    except Exception as exc:
        logger.error(f"Module {module_name} execution failed: {exc}", exc_info=True)
        return False


def list_modules():
    """Display available modules."""
    print("\n" + "=" * 70)
    print("KHORA MODULE REGISTRY".center(70))
    print("=" * 70)
    for name, info in sorted(MODULE_INFO.items()):
        critical = "[CRITICAL]" if info["critical"] else ""
        print(f"\n  [{info['type']:10}] {name:15} {critical}")
        print(f"      -> {info['desc']}")
    print("\n" + "=" * 70 + "\n")


def create_session_report(target, lhost, lport, modules_run, success_count, start_time, end_time):
    """Create a JSON report of the assessment session."""
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
        "success_rate": f"{(success_count / len(modules_run) * 100):.1f}%",
        "log_file": str(LOG_FILE),
        "results_directory": str(RESULTS_DIR),
        "exploits_directory": str(EXPLOITS_DIR),
    }

    report_file = RESULTS_DIR / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as handle:
        json.dump(report, handle, indent=2)

    logger.info(f"Session report: {report_file}")
    return report_file


def validate_ip(ip_string):
    """Validate an IP address."""
    try:
        import ipaddress

        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Khora Framework v2.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 client.py 192.168.1.100 10.10.14.1
  python3 client.py 192.168.1.100 10.10.14.1 -m backdoor
  python3 client.py 192.168.1.100 10.10.14.1 -p 8888 --workers 3
  python3 client.py 192.168.1.100 10.10.14.1 --sequential -v
  python3 client.py --list
        """,
    )

    parser.add_argument("target", nargs="?", help="Target IP address")
    parser.add_argument("lhost", nargs="?", help="Listener address")
    parser.add_argument("-m", "--module", help="Execute a specific module")
    parser.add_argument("--chain", help="Execute a pre-built assessment chain")
    parser.add_argument("--list-chains", action="store_true", help="List available chain profiles")
    parser.add_argument("-p", "--port", type=int, default=4444, help="Listener port (default: 4444)")
    parser.add_argument("--session", help="Reuse an existing session ID")
    parser.add_argument("--assessor", default="Khora", help="Assessor name for session metadata")
    parser.add_argument("--list", action="store_true", help="List available modules")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--sequential", action="store_true", help="Run modules sequentially")
    parser.add_argument("--workers", type=int, default=5, help="Max parallel workers (default: 5)")

    args = parser.parse_args()

    if args.list:
        list_modules()
        return

    if args.list_chains:
        list_attack_profiles()
        return

    if not args.target or not args.lhost:
        parser.print_help()
        return

    session_manager = SessionManager()
    if args.session and session_manager.get_session(args.session):
        session_id = args.session
        session_manager.start_session(session_id)
    else:
        session_id = session_manager.create_session(args.target, args.assessor)
        session_manager.start_session(session_id)

    logger.info(f"Session ID: {session_id}")

    if not validate_ip(args.target) or not validate_ip(args.lhost):
        logger.error("Invalid IP address format")
        return

    logger.info(f"Target: {args.target} | LHOST: {args.lhost}:{args.port}")

    modules = list(MODULE_INFO.keys())
    start_time = datetime.now()

    if args.module:
        if args.module not in modules:
            logger.error(f"Unknown module: {args.module}")
            return

        logger.info(f"Running module: {args.module}")
        success = execute_module(args.module, args.target, args.lhost, args.port)
        modules_run = [args.module]
        success_count = 1 if success else 0
        session_manager.log_module_execution(args.module, "success" if success else "failed")
    elif args.chain:
        if args.chain not in ATTACK_PROFILES:
            logger.error(f"Unknown chain profile: {args.chain}")
            print(f"Unknown chain profile: {args.chain}")
            return

        chain = load_chain_profile(args.chain, args.target, args.lhost, args.port)
        logger.info(f"Executing chain: {args.chain}")
        result = chain.execute()
        chain.save_chain()

        modules_run = list(result["results"].keys())
        success_count = result["successful"]

        for module_name, step in result["results"].items():
            session_manager.log_module_execution(module_name, step["status"], step)
    else:
        logger.info("Running full assessment...")
        modules_run = []
        success_count = 0

        if args.sequential:
            for module_name in modules:
                success = execute_module(module_name, args.target, args.lhost, args.port)
                if success:
                    success_count += 1
                modules_run.append(module_name)
                session_manager.log_module_execution(module_name, "success" if success else "failed")
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(execute_module, mod, args.target, args.lhost, args.port): mod
                    for mod in modules
                }

                for future in as_completed(futures):
                    module_name = futures[future]
                    try:
                        success = future.result()
                        if success:
                            success_count += 1
                        session_manager.log_module_execution(module_name, "success" if success else "failed")
                    except Exception as exc:
                        logger.error(f"Exception in {module_name}: {exc}")
                        session_manager.log_module_execution(module_name, "failed", {"error": str(exc)})
                    modules_run.append(module_name)

    end_time = datetime.now()

    report_file = create_session_report(
        args.target, args.lhost, args.port, modules_run, success_count, start_time, end_time
    )

    print("\n" + "=" * 70)
    print("ASSESSMENT SUMMARY".center(70))
    print("=" * 70)
    print(f"Target:           {args.target}")
    print(f"LHOST:            {args.lhost}:{args.port}")
    print(f"Modules Executed: {len(modules_run)}/{len(modules)}")
    print(f"Successful:       {success_count}")
    print(f"Duration:         {(end_time - start_time).total_seconds():.1f}s")
    print(f"Results:          {RESULTS_DIR}/")
    print(f"Exploits:         {EXPLOITS_DIR}/")
    print(f"Report:           {report_file}")
    print("=" * 70 + "\n")

    session_manager.end_session(session_id)
    logger.info("Assessment complete")


if __name__ == "__main__":
    main()
