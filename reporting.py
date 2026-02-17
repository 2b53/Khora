"""
Reporting Engine - Comprehensive Exploitation & Assessment Reports
HTML/JSON/PDF Generation, Metrics, Timeline Analysis
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import base64
import subprocess
import sys

logger = logging.getLogger("Khora.Reporting")

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logger.warning("reportlab not installed - PDF generation will be disabled. Install with: pip install reportlab")

class ExploitationReport:
    """Generate comprehensive exploitation reports"""
    
    def __init__(self, assessment_name: str, target: str, assessor: str = "Khora"):
        self.assessment_name = assessment_name
        self.target = target
        self.assessor = assessor
        self.start_time = datetime.now()
        self.findings = []
        self.vulnerabilities = []
        self.exploited_modules = []
        self.timeline = []
        
        Path("reports").mkdir(exist_ok=True)
    
    def add_finding(self, severity: str, title: str, description: str, 
                   remediation: str = None, evidence: str = None):
        """Add security finding to report"""
        finding = {
            'severity': severity,  # critical, high, medium, low, info
            'title': title,
            'description': description,
            'remediation': remediation,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat(),
            'module': None  # Will be set by exploitation context
        }
        self.findings.append(finding)
        logger.info(f"Finding added: [{severity}] {title}")
    
    def add_vulnerability(self, cve: str, product: str, version: str, 
                         severity: str = "high", exploitable: bool = True):
        """Add discovered vulnerability"""
        vuln = {
            'cve': cve,
            'product': product,
            'version': version,
            'severity': severity,
            'exploitable': exploitable,
            'discovered_at': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        logger.info(f"Vulnerability found: {cve} in {product}")
    
    def add_module_execution(self, module: str, status: str, 
                            duration: float, success_count: int = None, 
                            findings_count: int = None):
        """Track module execution"""
        execution = {
            'module': module,
            'status': status,
            'duration_seconds': duration,
            'success_count': success_count,
            'findings_count': findings_count,
            'timestamp': datetime.now().isoformat()
        }
        self.exploited_modules.append(execution)
        self.timeline.append({
            'time': datetime.now().isoformat(),
            'event': f"Module {module} executed: {status}",
            'type': 'module_execution'
        })
        logger.info(f"Module execution tracked: {module} - {status}")
    
    def add_compromised_account(self, username: str, source: str, 
                               hash_type: str = None, cracked: bool = False):
        """Add compromised credentials to findings"""
        self.add_finding(
            'critical',
            f'Compromised Account: {username}',
            f'Account credentials discovered via {source}. "' +
            f'Hash type: {hash_type or "N/A"}. Cracked: {"Yes" if cracked else "No"}',
            remediation='Force password reset and enable MFA'
        )
    
    def add_privilege_escalation(self, method: str, from_user: str, to_user: str):
        """Add privilege escalation finding"""
        self.add_finding(
            'critical',
            f'Privilege Escalation: {from_user} → {to_user}',
            f'System is vulnerable to privilege escalation via {method}',
            remediation='Apply security patches and configure privilege escalation protections'
        )
    
    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary"""
        critical_count = len([f for f in self.findings if f['severity'] == 'critical'])
        high_count = len([f for f in self.findings if f['severity'] == 'high'])
        medium_count = len([f for f in self.findings if f['severity'] == 'medium'])
        low_count = len([f for f in self.findings if f['severity'] == 'low'])
        info_count = len([f for f in self.findings if f['severity'] == 'info'])
        
        risk_score = (critical_count * 10 + high_count * 5) / max(len(self.findings), 1)
        
        return {
            'assessment': self.assessment_name,
            'target': self.target,
            'assessor': self.assessor,
            'assessment_date': self.start_time.isoformat(),
            'duration_minutes': (datetime.now() - self.start_time).total_seconds() / 60,
            'risk_score': min(risk_score, 10),  # 0-10 scale
            'total_findings': len(self.findings),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'medium_findings': medium_count,
            'low_findings': low_count,
            'info_findings': info_count,
            'total_vulnerabilities': len(self.vulnerabilities),
            'modules_executed': len(self.exploited_modules),
            'compromised_accounts': len([f for f in self.findings if 'Compromised' in f['title']])
        }
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'report_type': 'Penetration Test Report',
                'generated_at': datetime.now().isoformat(),
                'tool': 'Khora Security Framework v2.1'
            },
            'executive_summary': self.generate_executive_summary(),
            'timeline': self.timeline,
            'modules_executed': self.exploited_modules,
            'vulnerabilities': self.vulnerabilities,
            'findings': self.findings
        }
        return json.dumps(report_data, indent=2)
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        summary = self.generate_executive_summary()
        critical_count = summary['critical_findings']
        high_count = summary['high_findings']
        
        # Color coding
        risk_color = '#d32f2f' if summary['risk_score'] > 8 else \
                    '#f57c00' if summary['risk_score'] > 5 else \
                    '#fbc02d' if summary['risk_score'] > 2 else \
                    '#388e3c'
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Penetration Test Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #1976d2; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-left: 5px solid {risk_color}; }}
        .risk-score {{ font-size: 3em; font-weight: bold; color: {risk_color}; text-align: center; }}
        .findings {{ background: white; padding: 20px; margin: 20px 0; }}
        .critical {{ background: #ffebee; border-left: 5px solid #d32f2f; padding: 10px; margin: 10px 0; }}
        .high {{ background: #ffe8e6; border-left: 5px solid #f57c00; padding: 10px; margin: 10px 0; }}
        .medium {{ background: #fffde7; border-left: 5px solid #fbc02d; padding: 10px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #1976d2; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Penetration Test Report</h1>
        <p>Target: {self.target}</p>
        <p>Date: {summary['assessment_date']}</p>
        <p style="margin-top: 10px; font-size: 0.9em;"><strong>Assessed by: 2b53</strong></p>
    </div>
    
    <div class="summary">
        <h2>Risk Assessment</h2>
        <div class="risk-score">{summary['risk_score']:.1f}/10</div>
        <p>Critical Issues: {critical_count} | High Issues: {high_count}</p>
        <p>Duration: {summary['duration_minutes']:.1f} minutes</p>
    </div>
    
    <div class="findings">
        <h2>Key Findings Summary</h2>
        <table>
            <tr>
                <th>Total Findings</th>
                <th>Critical</th>
                <th>High</th>
                <th>Vulnerabilities Found</th>
                <th>Modules Executed</th>
            </tr>
            <tr>
                <td>{summary['total_findings']}</td>
                <td>{critical_count}</td>
                <td>{high_count}</td>
                <td>{summary['total_vulnerabilities']}</td>
                <td>{summary['modules_executed']}</td>
            </tr>
        </table>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
"""
        
        for finding in sorted(self.findings, key=lambda x: 
                             {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x['severity'], 5)):
            css_class = finding['severity'].lower()
            html += f"""
        <div class="{css_class}">
            <h3>{finding['title']} [<em>{finding['severity'].upper()}</em>]</h3>
            <p><strong>Description:</strong> {finding['description']}</p>
            {f"<p><strong>Remediation:</strong> {finding['remediation']}</p>" if finding['remediation'] else ""}
            <p><em>Found: {finding['timestamp']}</em></p>
        </div>
"""
        
        html += """
    </div>
    
    <div class="summary">
        <h2>Recommendations</h2>
        <ol>
            <li>Address all critical and high-severity findings immediately</li>
            <li>Implement multi-factor authentication across all systems</li>
            <li>Deploy intrusion detection and prevention systems</li>
            <li>Conduct regular security awareness training</li>
            <li>Establish patch management procedures</li>
            <li>Schedule follow-up penetration test after remediations</li>
        </ol>
    </div>
    
    <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ccc; color: #666;">
        <p>Report generated by Khora Security Framework v2.1</p>
        <p><strong>Penetration Tester: 2b53</strong> | <em>CONFIDENTIAL - For authorized use only</em></p>
    </footer>
</body>
</html>"""
        
        return html
    
    def generate_pdf_report(self) -> bytes:
        """Generate PDF report (requires reportlab)"""
        if not PDF_AVAILABLE:
            logger.warning("reportlab not available - cannot generate PDF. Install with: pip install reportlab")
            return None
        
        try:
            from io import BytesIO
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            
            summary = self.generate_executive_summary()
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1976d2'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            story.append(Paragraph("PENETRATION TEST REPORT", title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Header info
            header_data = [
                ['Target:', self.target],
                ['Assessment:', self.assessment_name],
                ['Assessor:', '2b53'],
                ['Date:', summary['assessment_date']],
                ['Framework:', 'Khora v2.1']
            ]
            header_table = Table(header_data, colWidths=[2*inch, 4*inch])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e3f2fd')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(header_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Risk Score
            risk_score = summary['risk_score']
            risk_color = colors.HexColor('#d32f2f') if risk_score > 8 else \
                        colors.HexColor('#f57c00') if risk_score > 5 else colors.HexColor('#388e3c')
            
            risk_style = ParagraphStyle(
                'RiskScore',
                parent=styles['Heading2'],
                fontSize=48,
                textColor=risk_color,
                alignment=TA_CENTER
            )
            story.append(Paragraph(f"{risk_score:.1f}/10", risk_style))
            story.append(Paragraph("Risk Score", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Findings Summary
            story.append(Paragraph("FINDINGS SUMMARY", styles['Heading2']))
            findings_data = [
                ['Severity', 'Count'],
                ['Critical', str(summary['critical_findings'])],
                ['High', str(summary['high_findings'])],
                ['Medium', str(summary['medium_findings'])],
                ['Low', str(summary['low_findings'])],
                ['Info', str(summary['info_findings'])]
            ]
            findings_table = Table(findings_data, colWidths=[3*inch, 2*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(findings_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Detailed Findings
            if self.findings:
                story.append(Paragraph("DETAILED FINDINGS", styles['Heading2']))
                for i, finding in enumerate(self.findings[:10], 1):  # Limit to first 10
                    severity = finding['severity'].upper()
                    story.append(Paragraph(f"{i}. [{severity}] {finding['title']}", styles['Heading3']))
                    story.append(Paragraph(f"Description: {finding['description']}", styles['Normal']))
                    if finding.get('remediation'):
                        story.append(Paragraph(f"Remediation: {finding['remediation']}", styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("---", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("Report generated by Khora Security Framework v2.1", styles['Normal']))
            story.append(Paragraph("<b>Penetration Tester:</b> 2b53 | CONFIDENTIAL", styles['Normal']))
            
            doc.build(story)
            return buffer.getvalue()
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None
        """Save report to file (json, html, or pdf)
        
        Examples:
            report.save_report(format='pdf')   # Generates PDF
            report.save_report(format='html')  # Generates HTML
            report.save_report(format='json')  # Generates JSON (default)
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            
            if format.lower() == 'json':
                report_file = Path("reports") / f"report_{self.target}_{timestamp}.json"
                content = self.generate_json_report()
            elif format.lower() == 'html':
                report_file = Path("reports") / f"report_{self.target}_{timestamp}.html"
                content = self.generate_html_report()
            elif format.lower() == 'pdf':
                if not PDF_AVAILABLE:
                    print("[!] reportlab not installed. Install with: pip install reportlab")
                    return None
                report_file = Path("reports") / f"report_{self.target}_{timestamp}.pdf"
                content = self.generate_pdf_report()
                if content is None:
                    return None
            else:
                raise ValueError(f"Unknown format: {format}. Use 'json', 'html', or 'pdf'")
            
            with open(report_file, 'wb' if format.lower() == 'pdf' else 'w') as f:
                f.write(content)
            
            logger.info(f"Report saved: {report_file}")
            print(f"[✓] {format.upper()} Report saved: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print(f"[!] Report generation failed: {e}")
            return None
    
    def print_summary(self):
        """Print report summary to console"""
        summary = self.generate_executive_summary()
        
        print(f"\n{'='*70}")
        print(f"ASSESSMENT SUMMARY".center(70))
        print('='*70)
        print(f"Target: {summary['target']}")
        print(f"Assessment Date: {summary['assessment_date']}")
        print(f"Risk Score: {summary['risk_score']:.1f}/10")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"  - Critical: {summary['critical_findings']}")
        print(f"  - High: {summary['high_findings']}")
        print(f"Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Modules Executed: {summary['modules_executed']}")
        print(f"Duration: {summary['duration_minutes']:.1f} minutes")
        print('='*70 + "\n")
    
    def save_report(self, format: str = 'json') -> Path:
        """Save report to file (json, html, or pdf)
        
        Examples:
            report.save_report(format='pdf')   # Generates PDF
            report.save_report(format='html')  # Generates HTML
            report.save_report(format='json')  # Generates JSON (default)
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            
            if format.lower() == 'json':
                report_file = Path("reports") / f"report_{self.target}_{timestamp}.json"
                content = self.generate_json_report()
            elif format.lower() == 'html':
                report_file = Path("reports") / f"report_{self.target}_{timestamp}.html"
                content = self.generate_html_report()
            elif format.lower() == 'pdf':
                if not PDF_AVAILABLE:
                    print("  [!] reportlab not installed. Install with: pip install reportlab")
                    return None
                report_file = Path("reports") / f"report_{self.target}_{timestamp}.pdf"
                content = self.generate_pdf_report()
                if content is None:
                    return None
            else:
                raise ValueError(f"Unknown format: {format}. Use 'json', 'html', or 'pdf'")
            
            with open(report_file, 'wb' if format.lower() == 'pdf' else 'w') as f:
                f.write(content)
            
            logger.info(f"Report saved: {report_file}")
            print(f"[✓] {format.upper()} Report saved: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print(f"[!] Report generation failed: {e}")
            return None


def generate_comparison_report(target1_file: str, target2_file: str) -> str:
    """Generate comparison report between two assessments"""
    try:
        with open(target1_file) as f:
            report1 = json.load(f)
        with open(target2_file) as f:
            report2 = json.load(f)
        
        comparison = {
            'report1': report1['metadata'],
            'report2': report2['metadata'],
            'summary1': report1['executive_summary'],
            'summary2': report2['executive_summary'],
            'improvements': []
        }
        
        # Calculate improvements
        risk_improvement = report1['executive_summary']['risk_score'] - \
                          report2['executive_summary']['risk_score']
        if risk_improvement > 0:
            comparison['improvements'].append(
                f"Risk score improved by {risk_improvement:.1f} points"
            )
        
        finding_reduction = report1['executive_summary']['total_findings'] - \
                           report2['executive_summary']['total_findings']
        if finding_reduction > 0:
            comparison['improvements'].append(
                f"{finding_reduction} findings remediated"
            )
        
        return json.dumps(comparison, indent=2)
    
    except Exception as e:
        logger.error(f"Comparison failed: {e}")
        return None


if __name__ == "__main__":
    import argparse
    
    print("\n" + "="*70)
    print("  KHORA REPORTING ENGINE v2.1")
    print("  Penetration Testing Report Generator (by 2b53)")
    print("="*70 + "\n")
    
    parser = argparse.ArgumentParser(description="Generate Khora penetration test reports")
    parser.add_argument("--target", default="192.168.1.100", help="Target IP address")
    parser.add_argument("--format", choices=['json', 'html', 'pdf'], default='pdf', 
                       help="Report format (json, html, or pdf)")
    parser.add_argument("--demo", action='store_true', help="Generate demo report with sample findings")
    args = parser.parse_args()
    
    # Create report
    report = ExploitationReport("Security Assessment", args.target, assessor="2b53")
    
    if args.demo:
        print("[*] Generating demo report with sample findings...\n")
        
        # Add sample findings
        report.add_finding(
            severity="critical",
            title="Remote Code Execution (RCE)",
            description="Apache Struts2 vulnerable to OGNL injection (CVE-2017-5638)",
            remediation="Update Apache Struts2 to version 2.5.12+",
            evidence="http://192.168.1.100:8080/admin/user.action?action=list"
        )
        
        report.add_finding(
            severity="high",
            title="Unpatched System",
            description="Windows Server 2016 vulnerable to EternalBlue (MS17-010)",
            remediation="Apply Windows security patches KB4012212, KB4012213, KB4013429",
            evidence="SMB port 445 responding with vulnerable signature"
        )
        
        report.add_finding(
            severity="high",
            title="Weak Credentials",
            description="Default credentials found on network devices",
            remediation="Change all default passwords immediately",
            evidence="admin:admin on network switch"
        )
        
        report.add_finding(
            severity="medium",
            title="Missing Security Headers",
            description="HTTP security headers (CSP, X-Frame-Options) not configured",
            remediation="Implement security headers in web server configuration",
            evidence="HTTP response headers analysis"
        )
        
        report.add_finding(
            severity="medium",
            title="Unencrypted Traffic",
            description="FTP and Telnet services running unencrypted",
            remediation="Disable FTP/Telnet, use SFTP and SSH instead",
            evidence="Packet capture shows cleartext credentials"
        )
        
        report.add_vulnerability(
            cve="CVE-2017-5638",
            product="Apache Struts2",
            version="2.3.x - 2.5.10",
            severity="critical",
            exploitable=True
        )
        
        report.add_vulnerability(
            cve="CVE-2017-0144",
            product="Windows SMBv1",
            version="All versions",
            severity="critical",
            exploitable=True
        )
    else:
        print(f"[*] Generate basic report for {args.target}...\n")
        report.add_finding(
            severity="high",
            title="Example Finding",
            description="This is an example security finding",
            remediation="Implement recommended controls"
        )
    
    # Generate report
    print(f"[*] Generating {args.format.upper()} report...")
    output_file = report.save_report(format=args.format)
    
    if output_file:
        print(f"[✓] Report generated successfully!\n")
        print(f"    Location: {output_file.absolute()}")
        print(f"    Size: {output_file.stat().st_size} bytes")
        
        # Print summary
        report.print_summary()
        
        if args.format.lower() == 'pdf':
            print(f"\n[✓] PDF report ready - Open with your PDF viewer")
        elif args.format.lower() == 'html':
            print(f"\n[✓] HTML report ready - Open with your web browser")
        elif args.format.lower() == 'json':
            print(f"\n[✓] JSON report ready - Can be parsed programmatically")
    else:
        print(f"\n[!] Report generation failed")
        sys.exit(1)
    
    print("\n" + "="*70 + "\n")