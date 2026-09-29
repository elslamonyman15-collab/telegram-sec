#!/usr/bin/env python3
"""
Report Analyzer for Cyber Forensics Toolkit v8.0
Analyzes forensic reports and presents findings in user-friendly format
"""

import os
import json
import re
from datetime import datetime
from collections import defaultdict
from pathlib import Path


class ReportAnalyzer:
    """Analyzes forensic reports and extracts key findings"""
    
    def __init__(self, report_dir=None):
        self.report_dir = report_dir or os.path.join(
            os.path.expanduser("~"),
            "Desktop",
            "Cyber_Forensic_Report"
        )
        self.findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        self.summary = {}
        
    def analyze_reports(self):
        """Analyze all reports in the report directory"""
        if not os.path.exists(self.report_dir):
            return {
                'error': 'Report directory not found',
                'path': self.report_dir
            }
        
        self._analyze_network_forensics()
        self._analyze_process_anatomy()
        self._analyze_user_audit()
        self._analyze_persistence()
        self._analyze_filesystem()
        self._analyze_firewall()
        self._analyze_event_logs()
        self._analyze_registry()
        self._analyze_memory()
        self._analyze_artifacts()
        
        return self._generate_summary()
    
    def _analyze_network_forensics(self):
        """Analyze network forensics report"""
        report_file = os.path.join(self.report_dir, "Network_Deep_Analysis.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for suspicious connections
        suspicious_ports = ['4444', '5555', '6666', '31337', '12345', '54321', '1337']
        for port in suspicious_ports:
            if f":{port}" in content:
                self.findings['high'].append({
                    'category': 'Network',
                    'title': f'Suspicious port detected: {port}',
                    'description': f'Connection to known suspicious port {port} detected',
                    'recommendation': 'Investigate the process using this connection'
                })
        
        # Check for unusual number of connections
        established_count = content.count('ESTABLISHED')
        if established_count > 100:
            self.findings['medium'].append({
                'category': 'Network',
                'title': 'High number of established connections',
                'description': f'{established_count} established connections detected',
                'recommendation': 'Review network activity for potential malware communication'
            })
    
    def _analyze_process_anatomy(self):
        """Analyze process anatomy report"""
        report_file = os.path.join(self.report_dir, "Process_Anatomy.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for suspicious processes
        suspicious_processes = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'certutil']
        for proc in suspicious_processes:
            if proc in content.lower():
                self.findings['medium'].append({
                    'category': 'Process',
                    'title': f'Suspicious process detected: {proc}',
                    'description': f'Process {proc} found running (commonly used by malware)',
                    'recommendation': 'Verify this process is legitimate'
                })
        
        # Check for hidden processes
        if 'hidden' in content.lower():
            self.findings['high'].append({
                'category': 'Process',
                'title': 'Hidden processes detected',
                'description': 'Processes with hidden attributes detected',
                'recommendation': 'Investigate for rootkit or malware'
            })
    
    def _analyze_user_audit(self):
        """Analyze user audit report"""
        report_file = os.path.join(self.report_dir, "User_Privileges_Audit.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for unusual admin accounts
        admin_count = content.lower().count('administrator')
        if admin_count > 5:
            self.findings['high'].append({
                'category': 'User',
                'title': 'Multiple administrator accounts',
                'description': f'{admin_count} administrator accounts detected',
                'recommendation': 'Review all admin accounts and remove unnecessary ones'
            })
        
        # Check for disabled accounts
        if 'disabled' in content.lower():
            self.findings['low'].append({
                'category': 'User',
                'title': 'Disabled user accounts found',
                'description': 'Some user accounts are disabled',
                'recommendation': 'Review disabled accounts for cleanup'
            })
    
    def _analyze_persistence(self):
        """Analyze persistence mechanisms report"""
        report_file = os.path.join(self.report_dir, "Persistence_Mechanisms.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for suspicious startup items
        suspicious_paths = ['temp', 'appdata', 'downloads', 'public']
        for path in suspicious_paths:
            if path in content.lower():
                self.findings['high'].append({
                    'category': 'Persistence',
                    'title': f'Startup item in suspicious location: {path}',
                    'description': f'Program starting from {path} directory',
                    'recommendation': 'Investigate this startup item'
                })
        
        # Check for unusual scheduled tasks
        if 'schtasks' in content.lower() and len(content) > 5000:
            self.findings['medium'].append({
                'category': 'Persistence',
                'title': 'Many scheduled tasks detected',
                'description': 'Large number of scheduled tasks found',
                'recommendation': 'Review scheduled tasks for suspicious entries'
            })
    
    def _analyze_filesystem(self):
        """Analyze filesystem forensics report"""
        report_file = os.path.join(self.report_dir, "Modified_Files_Forensics.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for recently modified executables
        if content.count('.exe') > 10:
            self.findings['medium'].append({
                'category': 'File System',
                'title': 'Recently modified executables',
                'description': 'Multiple executable files modified recently',
                'recommendation': 'Review these files for potential infection'
            })
        
        # Check for suspicious locations
        suspicious_locations = ['temp', 'appdata', 'recycle']
        for loc in suspicious_locations:
            if loc in content.lower():
                self.findings['high'].append({
                    'category': 'File System',
                    'title': f'Files in suspicious location: {loc}',
                    'description': f'Executable files found in {loc} directory',
                    'recommendation': 'Investigate these files'
                })
    
    def _analyze_firewall(self):
        """Analyze firewall and hosts report"""
        report_file = os.path.join(self.report_dir, "Firewall_And_Hosts_Integrity.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for hosts file modifications
        if '127.0.0.1' in content and content.count('127.0.0.1') > 5:
            self.findings['medium'].append({
                'category': 'Network',
                'title': 'Hosts file modified',
                'description': 'Multiple entries in hosts file detected',
                'recommendation': 'Review hosts file for malicious redirects'
            })
        
        # Check for disabled firewall rules
        if 'block' in content.lower():
            self.findings['info'].append({
                'category': 'Firewall',
                'title': 'Firewall rules reviewed',
                'description': 'Firewall configuration analyzed',
                'recommendation': 'Ensure firewall is properly configured'
            })
    
    def _analyze_event_logs(self):
        """Analyze security event logs"""
        report_file = os.path.join(self.report_dir, "Security_Event_Logs.txt")
        if not os.path.exists(report_file):
            return
        
        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for failed logins
        failed_login_count = content.lower().count('failed')
        if failed_login_count > 10:
            severity = 'critical' if failed_login_count > 50 else 'high'
            self.findings[severity].append({
                'category': 'Security',
                'title': f'Multiple failed login attempts: {failed_login_count}',
                'description': f'{failed_login_count} failed login attempts detected',
                'recommendation': 'Possible brute force attack - investigate source IPs'
            })
        
        # Check for PowerShell events
        if 'powershell' in content.lower() and '4104' in content:
            self.findings['high'].append({
                'category': 'Security',
                'title': 'Suspicious PowerShell activity',
                'description': 'PowerShell script block logging detected',
                'recommendation': 'Review PowerShell execution for malicious activity'
            })
    
    def _analyze_registry(self):
        """Analyze registry forensics"""
        registry_dir = os.path.join(self.report_dir, "REGISTRY")
        if not os.path.exists(registry_dir):
            return
        
        # Check if registry hives were extracted
        hives = ['SAM.hive', 'SYSTEM.hive', 'SECURITY.hive', 'SOFTWARE.hive']
        extracted_hives = [h for h in hives if os.path.exists(os.path.join(registry_dir, h))]
        
        if extracted_hives:
            self.findings['info'].append({
                'category': 'Registry',
                'title': 'Registry hives extracted',
                'description': f'{len(extracted_hives)} registry hives available for offline analysis',
                'recommendation': 'Use specialized tools to analyze registry hives'
            })
    
    def _analyze_memory(self):
        """Analyze memory forensics"""
        memory_dir = os.path.join(self.report_dir, "MEMORY")
        if not os.path.exists(memory_dir):
            return
        
        # Check memory files
        memory_files = os.listdir(memory_dir) if os.path.exists(memory_dir) else []
        
        if memory_files:
            self.findings['info'].append({
                'category': 'Memory',
                'title': 'Memory information collected',
                'description': f'{len(memory_files)} memory analysis files available',
                'recommendation': 'Review process memory and loaded DLLs'
            })
    
    def _analyze_artifacts(self):
        """Analyze advanced artifacts"""
        artifacts_dir = os.path.join(self.report_dir, "ARTIFACTS")
        if not os.path.exists(artifacts_dir):
            return
        
        # Check artifact files
        artifact_files = os.listdir(artifacts_dir) if os.path.exists(artifacts_dir) else []
        
        if artifact_files:
            self.findings['info'].append({
                'category': 'Artifacts',
                'title': 'Advanced artifacts collected',
                'description': f'{len(artifact_files)} forensic artifacts available (Prefetch, Amcache, SRUM, etc.)',
                'recommendation': 'Use specialized tools for deep artifact analysis'
            })
    
    def _generate_summary(self):
        """Generate summary of findings"""
        total_findings = sum(len(v) for v in self.findings.values())
        
        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'report_directory': self.report_dir,
            'total_findings': total_findings,
            'findings_by_severity': {
                'critical': len(self.findings['critical']),
                'high': len(self.findings['high']),
                'medium': len(self.findings['medium']),
                'low': len(self.findings['low']),
                'info': len(self.findings['info'])
            },
            'findings': self.findings,
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self):
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Critical recommendations
        if self.findings['critical']:
            recommendations.append({
                'priority': 'Critical',
                'action': 'Address all critical findings immediately',
                'details': f'{len(self.findings["critical"])} critical issues require immediate attention'
            })
        
        # High priority recommendations
        if self.findings['high']:
            recommendations.append({
                'priority': 'High',
                'action': 'Investigate high-severity findings',
                'details': f'{len(self.findings["high"])} high-severity issues detected'
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'Medium',
            'action': 'Review all findings',
            'details': 'Complete investigation of all detected issues'
        })
        
        recommendations.append({
            'priority': 'Low',
            'action': 'Implement preventive measures',
            'details': 'Strengthen security based on findings'
        })
        
        return recommendations


if __name__ == "__main__":
    analyzer = ReportAnalyzer()
    results = analyzer.analyze_reports()
    
    print("=== FORENSIC REPORT ANALYSIS ===")
    print(f"Report Directory: {results['report_directory']}")
    print(f"Analysis Time: {results['timestamp']}")
    print(f"\nTotal Findings: {results['total_findings']}")
    print("\nFindings by Severity:")
    for severity, count in results['findings_by_severity'].items():
        print(f"  {severity.capitalize()}: {count}")
    
    print("\n=== CRITICAL FINDINGS ===")
    for finding in results['findings']['critical']:
        print(f"\n{finding['title']}")
        print(f"  Description: {finding['description']}")
        print(f"  Recommendation: {finding['recommendation']}")
