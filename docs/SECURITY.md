# KHORA Security Policy & Responsible Disclosure

## Executive Summary

Khora is committed to responsible security practices. This document outlines security policies, vulnerability reporting procedures, and safe usage guidelines.

## Scope

This policy applies to:
- Khora framework source code
- All modules and scripts
- Generated payloads (msfvenom, custom)
- C2 infrastructure
- Sample configurations

## Legal Framework

### Authorized Testing Only

Khora may only be used on:
- Systems you own and control
- Systems with explicit written authorization
- Controlled lab environments (HTB, proving grounds, etc.)
- Approved security assessments

### Prohibited Use

- Unauthorized access to computer systems (CFAA violation in US)
- Unauthorized data extraction
- Denial of service attacks
- Malware distribution
- Any illegal activity

## Vulnerability Reporting (Responsible Disclosure)

### Report Security Issues To

**Discord**: 2b53
**Email**: security@khora-framework.local (if applicable)

### What To Include

1. **Detailed description** of the vulnerability
2. **Step-by-step reproduction** steps
3. **Potential impact** assessment
4. **Severity level** (critical, high, medium, low)
5. **Proof-of-concept** (if applicable)
6. **Your contact** information for follow-up

### Response Timeline

- **Acknowledgment**: Within 7 days
- **Investigation**: Within 14 days
- **Patch release**: Within 30 days (for critical issues)
- **Public disclosure**: After patch release

## Safe Harbor Protection

Researchers who report vulnerabilities in good faith are protected from legal action if:
- Vulnerability found in Khora code/modules only
- Reported to security team before public disclosure
- No systems accessed beyond proof-of-concept
- No data exfiltrated
- Report is truthful and made in good faith

## Code Security Standards

### Input Validation
- All user input validated before processing
- Arguments type-checked and sanitized
- IP addresses validated with ipaddress module
- File paths validated to prevent traversal

### Dependency Management
- Requirements locked with specific versions
- Regular security audits of dependencies
- Vulnerable packages flagged and updated
- Python 3.8+ only (Python 2 end-of-life)

### Error Handling
- Comprehensive logging
- Graceful error handling
- No sensitive data in error messages
- Exception chain included in logs

### Access Control
- Scripts run with minimum required privileges
- Root access only when necessary
- Windows UAC compatibility
- Audit trails for all privileged operations

## Framework Usage Warnings

### High-Risk Operations

- **C2 Infrastructure**: Activates only with explicit user confirmation
- **Reverse Shells**: Generated locally, not auto-deployed
- **C Exploit Compilation**: GCC warnings parsed for security issues
- **Hash Cracking**: Resource-intensive, monitor system load

### System Impact

- **Disk Space**: Results/logs/payloads can consume 100+ MB
- **Network Impact**: Nmap/DNS spoof can generate significant traffic
- **CPU Usage**: Hash cracking parallelizes across cores
- **Memory**: Buffer allocation in exploits monitored

## Privacy & Data Protection

### What Khora Collects

- Scan results (local storage only)
- Session logs (local storage only)
- Command history (in-memory only)
- No telemetry, no tracking, no external communication

### Data Handling

- All data stored locally in 
esults/ and logs/
- No parsing, analysis, or external transmission
- User responsible for data protection
- Encryption recommended for sensitive engagements

## Incident Response

### If Khora Is Compromised

1. Immediately discontinue use
2. Review compromise scope
3. Report to security team
4. Patch security vulnerabilities
5. Rotate all credentials/keys
6. Audit affected systems

### If Khora Is Misused

Owner/Author will:
- Not provide technical support for illegal activities
- Cooperate with law enforcement if required
- Remove malicious forks from repositories
- Update documentation to prevent misuse

## Compliance Statements

### CFAA (Computer Fraud & Abuse Act)
Users must comply with US and local laws regarding unauthorized access

### GDPR Compliance
Framework uses no personal data; users must ensure compliance

### Terms of Service
Users must comply with system owner's Terms of Service

## Testing Safely

### Best Practices

1. **Isolated Environment**: Use VPN or air-gapped networks
2. **Documentation**: Keep detailed pentest notes
3. **Authorization**: Always get written permission
4. **Rules of Engagement**: Agree on scope and limits beforehand
5. **Backup**: Create target backups before testing
6. **Communication**: Report findings to stakeholders regularly
7. **Cleanup**: Remove all payloads/implants after testing completes

### Lab Environments

- **HackTheBox**: Authorized penetration testing platform
- **TryHackMe**: Legal security training
- **DVWA**: Deliberately vulnerable web app
- **Metasploitable**: Intentionally vulnerable Linux
- **Windows Server 2012 (Eval)**: Practice Windows exploitation

## Support & Escalation

### Issue Categories

1. **False Positives**: Report via GitHub Issues
2. **Module Failures**: Include logs: logs/khora_*.log
3. **Performance Issues**: System specs required
4. **Security Concerns**: Use responsible disclosure

### Getting Help

- Community Discord (2b53)
- GitHub Issues (with minimal details)
- Security email (for vulnerabilities)

## Framework Limitations & Disclaimers

### Not Responsible For

- Unauthorized access using framework
- Data breach or loss
- System compromise
- Legal consequences
- Ethical violations
- Target defense measures

### Framework Disclaimers

- All modules should be tested in controlled environments first
- Some features require root/administrator privileges
- Antivirus software may flag payloads (expected behavior)
- Network security appliances may detect/block traffic
- Updated software may patch exploited vulnerabilities

## Version & Updates

- **Current Version**: Khora v2.1
- **Last Updated**: 2026-02-17
- **Maintenance Status**: Active development
- **Security Patches**: As needed

---

**By using Khora, you agree to all terms and conditions in this policy.**

---
