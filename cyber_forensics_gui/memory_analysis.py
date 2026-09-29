#!/usr/bin/env python3
"""
Advanced Memory Analysis Module for Cyber Forensics Toolkit v8.0
Analyzes process memory, extracts artifacts, and detects memory-based threats
"""

import os
import sys
import logging
import subprocess
import json
from datetime import datetime
from collections import defaultdict
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MemoryAnalyzer:
    """Advanced memory analysis for forensic investigation"""
    
    def __init__(self):
        self.process_list = []
        self.memory_regions = {}
        self.extracted_artifacts = []
        
    def get_process_list(self):
        """Get detailed list of all running processes"""
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/V'],
                capture_output=True,
                text=True
            )
            
            processes = []
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.replace('"', '').split(',')
                    if len(parts) >= 8:
                        processes.append({
                            'name': parts[0],
                            'pid': parts[1],
                            'session_name': parts[2],
                            'session_num': parts[3],
                            'mem_usage': parts[4],
                            'status': parts[5],
                            'user_name': parts[6],
                            'cpu_time': parts[7],
                            'window_title': parts[8] if len(parts) > 8 else ''
                        })
            
            self.process_list = processes
            return processes
            
        except Exception as e:
            logger.error(f"Error getting process list: {e}")
            return []
    
    def get_process_memory_info(self, pid):
        """Get detailed memory information for a specific process"""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'WorkingSetSize,PageFileUsage,VirtualSize'],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                values = lines[1].split()
                if len(values) >= 3:
                    return {
                        'working_set_size': int(values[0]),
                        'page_file_usage': int(values[1]),
                        'virtual_size': int(values[2])
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting process memory info: {e}")
            return None
    
    def detect_suspicious_processes(self):
        """Detect suspicious processes based on memory and behavior"""
        suspicious = []
        
        processes = self.get_process_list()
        
        # Suspicious process names
        suspicious_names = [
            'powershell', 'cmd', 'wscript', 'cscript', 'mshta',
            'rundll32', 'certutil', 'regsvr32', 'bitsadmin',
            'wmic', 'netsh', 'sc', 'schtasks'
        ]
        
        # Suspicious command line patterns
        suspicious_patterns = [
            r'-enc.*[A-Za-z0-9+/=]{20,}',  # Base64 encoded commands
            r'Invoke-Expression',  # PowerShell IEX
            r'FromBase64String',
            r'DownloadString',
            r'Invoke-WebRequest',
            r'New-Object.*Net.WebClient',
            r'hidden.*-windowstyle.*hidden',
            r'bypass.*-executionpolicy',
            r'echo.*\|.*cmd',
            r'certutil.*-decode',
            r'rundll32.*javascript'
        ]
        
        for proc in processes:
            name_lower = proc['name'].lower()
            
            # Check for suspicious process names
            if any(sus in name_lower for sus in suspicious_names):
                # Get command line
                cmd_line = self._get_process_command_line(proc['pid'])
                
                # Check for suspicious patterns in command line
                pattern_matches = []
                for pattern in suspicious_patterns:
                    if re.search(pattern, cmd_line, re.IGNORECASE):
                        pattern_matches.append(pattern)
                
                if pattern_matches:
                    suspicious.append({
                        'process': proc,
                        'reason': 'Suspicious command line pattern',
                        'patterns': pattern_matches,
                        'command_line': cmd_line,
                        'severity': 'High' if 'Invoke-Expression' in str(pattern_matches) else 'Medium'
                    })
                else:
                    suspicious.append({
                        'process': proc,
                        'reason': 'Suspicious process name',
                        'command_line': cmd_line,
                        'severity': 'Medium'
                    })
        
        return suspicious
    
    def _get_process_command_line(self, pid):
        """Get command line for a process"""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'CommandLine'],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                return lines[1].strip()
            
            return ''
            
        except Exception as e:
            logger.error(f"Error getting command line: {e}")
            return ''
    
    def detect_process_injection(self):
        """Detect potential process injection techniques"""
        injection_indicators = []
        
        processes = self.get_process_list()
        
        # Check for processes with unusual parent-child relationships
        parent_map = defaultdict(list)
        for proc in processes:
            try:
                parent_pid = self._get_parent_pid(proc['pid'])
                if parent_pid:
                    parent_map[parent_pid].append(proc)
            except Exception:
                pass
        
        # Suspicious parent-child relationships
        suspicious_parents = ['explorer.exe', 'svchost.exe', 'wininit.exe', 'lsass.exe']
        
        for parent_pid, children in parent_map.items():
            parent_name = self._get_process_name(parent_pid)
            
            if parent_name and parent_name.lower() in suspicious_parents:
                for child in children:
                    if child['name'].lower() not in ['cmd.exe', 'powershell.exe']:
                        injection_indicators.append({
                            'type': 'suspicious_parent_child',
                            'parent': parent_name,
                            'parent_pid': parent_pid,
                            'child': child['name'],
                            'child_pid': child['pid'],
                            'severity': 'High'
                        })
        
        return injection_indicators
    
    def _get_parent_pid(self, pid):
        """Get parent process ID"""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'ParentProcessId'],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                return int(lines[1].strip())
            
            return None
            
        except Exception:
            return None
    
    def _get_process_name(self, pid):
        """Get process name by PID"""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'Name'],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                return lines[1].strip()
            
            return None
            
        except Exception:
            return None
    
    def extract_clipboard_content(self):
        """Extract clipboard content (if accessible)"""
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                    data = win32clipboard.GetClipboardData()
                    return {
                        'type': 'text',
                        'content': data[:1000],  # Limit to 1000 chars
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
            finally:
                win32clipboard.CloseClipboard()
            
            return None
            
        except ImportError:
            logger.warning("win32clipboard not available")
            return None
        except Exception as e:
            logger.error(f"Error extracting clipboard: {e}")
            return None
    
    def detect_memory_less_malware(self):
        """Detect fileless malware indicators"""
        indicators = []
        
        # Check for PowerShell with encoded commands
        processes = self.get_process_list()
        
        for proc in processes:
            if proc['name'].lower() == 'powershell.exe':
                cmd_line = self._get_process_command_line(proc['pid'])
                
                # Check for fileless malware indicators
                if '-enc' in cmd_line or '-EncodedCommand' in cmd_line:
                    indicators.append({
                        'type': 'encoded_powershell',
                        'pid': proc['pid'],
                        'command_line': cmd_line[:200],
                        'severity': 'Critical'
                    })
                
                if 'Invoke-Expression' in cmd_line or 'IEX' in cmd_line:
                    indicators.append({
                        'type': 'iex_powershell',
                        'pid': proc['pid'],
                        'command_line': cmd_line[:200],
                        'severity': 'Critical'
                    })
        
        return indicators
    
    def analyze_loaded_dlls(self):
        """Analyze loaded DLLs for suspicious modules"""
        suspicious_dlls = []
        
        # Known suspicious DLLs
        suspicious_dll_names = [
            'amid.dll', 'amid64.dll',  # Anti-debugging
            'sbiedll.dll',  # Sandbox evasion
            'vmcheck.dll',  # VM detection
            'hook.dll', 'inject.dll',  # Injection
            'scyllahide.dll',  # Anti-debugging
            'kernelmode.dll',  # Kernel manipulation
        ]
        
        try:
            result = subprocess.run(
                ['tasklist', '/m'],
                capture_output=True,
                text=True
            )
            
            current_process = None
            for line in result.stdout.split('\n'):
                if '.exe' in line:
                    current_process = line.split()[0]
                elif current_process and '.dll' in line.lower():
                    dll_name = line.strip()
                    for sus_dll in suspicious_dll_names:
                        if sus_dll in dll_name.lower():
                            suspicious_dlls.append({
                                'process': current_process,
                                'dll': dll_name,
                                'severity': 'High'
                            })
                            break
        
        except Exception as e:
            logger.error(f"Error analyzing loaded DLLs: {e}")
        
        return suspicious_dlls
    
    def generate_memory_report(self):
        """Generate comprehensive memory analysis report"""
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_processes': len(self.get_process_list()),
            'suspicious_processes': self.detect_suspicious_processes(),
            'process_injection': self.detect_process_injection(),
            'memory_less_malware': self.detect_memory_less_malware(),
            'suspicious_dlls': self.analyze_loaded_dlls(),
            'clipboard_content': self.extract_clipboard_content()
        }
        
        return report


class VolatilityWrapper:
    """Wrapper for Volatility3 memory analysis (if available)"""
    
    def __init__(self):
        self.available = False
        self._check_availability()
    
    def _check_availability(self):
        """Check if Volatility3 is available"""
        try:
            result = subprocess.run(['vol', '--help'], capture_output=True, timeout=5)
            if result.returncode == 0:
                self.available = True
                logger.info("Volatility3 is available")
        except Exception:
            logger.info("Volatility3 not available, using Windows native tools")
    
    def analyze_memory_dump(self, dump_file):
        """Analyze memory dump file using Volatility3"""
        if not self.available:
            return None
        
        try:
            # Get process list from memory dump
            result = subprocess.run(
                ['vol', '-f', dump_file, 'windows.pslist'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'pslist': result.stdout,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            logger.error(f"Error analyzing memory dump: {e}")
            return None


if __name__ == "__main__":
    # Test the memory analyzer
    analyzer = MemoryAnalyzer()
    
    print("Running memory analysis...")
    report = analyzer.generate_memory_report()
    
    print(f"\nTotal Processes: {report['total_processes']}")
    print(f"Suspicious Processes: {len(report['suspicious_processes'])}")
    print(f"Process Injection Indicators: {len(report['process_injection'])}")
    print(f"Fileless Malware Indicators: {len(report['memory_less_malware'])}")
    print(f"Suspicious DLLs: {len(report['suspicious_dlls'])}")
    
    if report['clipboard_content']:
        print(f"\nClipboard Content: {report['clipboard_content']['content'][:100]}...")
