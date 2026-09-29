#!/usr/bin/env python3
"""
Real-Time Monitoring Daemon for Cyber Forensics Toolkit v8.0
Monitors processes, network connections, registry changes, and file system activity
"""

import os
import sys
import threading
import time
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
import subprocess
import ctypes
import ctypes.wintypes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealTimeMonitor:
    """Real-time monitoring daemon for system activity"""
    
    def __init__(self, callback=None):
        self.callback = callback  # Callback function for alerts
        self.running = False
        self.monitor_thread = None
        
        # Monitoring state
        self.process_baseline = set()
        self.network_baseline = set()
        self.registry_baseline = {}
        self.file_baseline = set()
        
        # Alert thresholds
        self.process_creation_threshold = 10  # processes per minute
        self.network_connection_threshold = 20  # connections per minute
        self.registry_change_threshold = 5  # changes per minute
        self.file_creation_threshold = 15  # files per minute
        
        # Alert history (for rate limiting)
        self.alert_history = deque(maxlen=100)
        self.alert_cooldown = 60  # seconds
        
        # Monitoring intervals
        self.process_interval = 5  # seconds
        self.network_interval = 5  # seconds
        self.registry_interval = 10  # seconds
        self.file_interval = 10  # seconds
        
    def start(self):
        """Start all monitoring threads"""
        if self.running:
            logger.warning("Monitor already running")
            return False
        
        self.running = True
        logger.info("Starting real-time monitoring daemon")
        
        # Initialize baselines
        self.initialize_baselines()
        
        # Start monitoring threads
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        return True
    
    def stop(self):
        """Stop all monitoring threads"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Real-time monitoring daemon stopped")
    
    def initialize_baselines(self):
        """Initialize baseline measurements"""
        logger.info("Initializing monitoring baselines...")
        
        # Process baseline
        try:
            result = subprocess.run(['tasklist'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[3:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        self.process_baseline.add(parts[0])
        except Exception as e:
            logger.error(f"Error initializing process baseline: {e}")
        
        # Network baseline
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        self.network_baseline.add(parts[1])
        except Exception as e:
            logger.error(f"Error initializing network baseline: {e}")
        
        logger.info(f"Baselines initialized: {len(self.process_baseline)} processes, {len(self.network_baseline)} connections")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Monitor processes
                self._monitor_processes()
                time.sleep(self.process_interval)
                
                if not self.running:
                    break
                
                # Monitor network
                self._monitor_network()
                time.sleep(self.network_interval)
                
                if not self.running:
                    break
                
                # Monitor registry (simplified - key changes)
                self._monitor_registry()
                time.sleep(self.registry_interval)
                
                if not self.running:
                    break
                
                # Monitor file system (simplified - temp directories)
                self._monitor_filesystem()
                time.sleep(self.file_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def _monitor_processes(self):
        """Monitor process creation and termination"""
        try:
            current_processes = set()
            suspicious_processes = []
            
            result = subprocess.run(['tasklist', '/FO', 'CSV'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.replace('"', '').split(',')
                    if len(parts) >= 2:
                        process_name = parts[0]
                        current_processes.add(process_name)
                        
                        # Check for suspicious processes
                        suspicious_keywords = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'certutil']
                        if any(keyword in process_name.lower() for keyword in suspicious_keywords):
                            suspicious_processes.append(process_name)
            
            # Detect new processes
            new_processes = current_processes - self.process_baseline
            if new_processes:
                logger.info(f"New processes detected: {new_processes}")
                if len(new_processes) > self.process_creation_threshold:
                    self._send_alert("High", f"Rapid process creation detected", 
                                   f"{len(new_processes)} new processes created in monitoring interval", "process")
            
            # Alert on suspicious processes
            if suspicious_processes:
                self._send_alert("Medium", "Suspicious process activity",
                               f"Suspicious processes running: {', '.join(suspicious_processes)}", "process")
            
            self.process_baseline = current_processes
            
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}")
    
    def _monitor_network(self):
        """Monitor network connections"""
        try:
            current_connections = set()
            suspicious_connections = []
            
            result = subprocess.run(['netstat', '-anob'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        connection = parts[1]
                        current_connections.add(connection)
                        
                        # Check for suspicious ports
                        suspicious_ports = ['4444', '5555', '6666', '31337', '12345', '54321', '1337']
                        port = connection.split(':')[-1] if ':' in connection else ''
                        if port in suspicious_ports:
                            suspicious_connections.append(connection)
            
            # Detect new connections
            new_connections = current_connections - self.network_baseline
            if new_connections:
                logger.info(f"New network connections: {len(new_connections)}")
                if len(new_connections) > self.network_connection_threshold:
                    self._send_alert("High", "Rapid network connection activity",
                                   f"{len(new_connections)} new connections established", "network")
            
            # Alert on suspicious connections
            if suspicious_connections:
                self._send_alert("Critical", "Suspicious network connection detected",
                               f"Connections on suspicious ports: {', '.join(suspicious_connections)}", "network")
            
            self.network_baseline = current_connections
            
        except Exception as e:
            logger.error(f"Error monitoring network: {e}")
    
    def _monitor_registry(self):
        """Monitor registry changes (simplified - checks specific keys)"""
        try:
            keys_to_monitor = [
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
            
            current_values = {}
            
            for key in keys_to_monitor:
                try:
                    result = subprocess.run(['reg', 'query', key], capture_output=True, text=True)
                    current_values[key] = result.stdout
                    
                    # Compare with baseline
                    if key in self.registry_baseline:
                        if current_values[key] != self.registry_baseline[key]:
                            self._send_alert("High", "Registry change detected",
                                           f"Registry key modified: {key}", "registry")
                
                except Exception:
                    pass
            
            self.registry_baseline = current_values
            
        except Exception as e:
            logger.error(f"Error monitoring registry: {e}")
    
    def _monitor_filesystem(self):
        """Monitor file system changes in critical directories"""
        try:
            critical_dirs = [
                os.path.expandvars(r'%TEMP%'),
                os.path.expandvars(r'%SystemRoot%\Temp'),
                os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
            ]
            
            current_files = set()
            
            for directory in critical_dirs:
                if os.path.exists(directory):
                    try:
                        for root, dirs, files in os.walk(directory):
                            for file in files:
                                file_path = os.path.join(root, file)
                                current_files.add(file_path)
                    except Exception:
                        pass
            
            # Detect new files
            new_files = current_files - self.file_baseline
            if new_files:
                logger.info(f"New files detected: {len(new_files)}")
                if len(new_files) > self.file_creation_threshold:
                    self._send_alert("High", "Rapid file creation detected",
                                   f"{len(new_files)} new files created in critical directories", "filesystem")
                
                # Check for suspicious file types
                suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr']
                suspicious_files = [f for f in new_files if any(f.lower().endswith(ext) for ext in suspicious_extensions)]
                if suspicious_files:
                    self._send_alert("Critical", "Suspicious executable created",
                                   f"New executable in critical directory: {suspicious_files[0]}", "filesystem")
            
            self.file_baseline = current_files
            
        except Exception as e:
            logger.error(f"Error monitoring filesystem: {e}")
    
    def _send_alert(self, severity, title, description, category):
        """Send alert via callback if configured"""
        # Check cooldown
        alert_key = f"{severity}:{title}"
        now = time.time()
        
        # Remove old alerts from history
        while self.alert_history and now - self.alert_history[0]['time'] > self.alert_cooldown:
            self.alert_history.popleft()
        
        # Check if similar alert was sent recently
        for alert in self.alert_history:
            if alert['key'] == alert_key and now - alert['time'] < self.alert_cooldown:
                return  # Skip duplicate alert within cooldown
        
        # Add to history
        self.alert_history.append({'key': alert_key, 'time': now})
        
        # Send alert
        alert_data = {
            'severity': severity,
            'title': title,
            'description': description,
            'category': category,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        logger.warning(f"ALERT [{severity}] {title}: {description}")
        
        if self.callback:
            try:
                self.callback(alert_data)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")


# Windows API constants for advanced monitoring
class WindowsEventMonitor:
    """Advanced monitoring using Windows Event Tracing (ETW)"""
    
    def __init__(self):
        self.running = False
        
    def start_etw_monitoring(self):
        """Start ETW-based monitoring (requires admin privileges)"""
        try:
            # This would use ETW APIs for more advanced monitoring
            # For now, we'll use WMI as a fallback
            self.start_wmi_monitoring()
        except Exception as e:
            logger.error(f"ETW monitoring not available: {e}")
    
    def start_wmi_monitoring(self):
        """Start WMI-based process monitoring"""
        try:
            import wmi
            self.wmi = wmi.WMI()
            self.running = True
            
            watcher = self.wmi.Win32_Process.watch_for("creation")
            
            while self.running:
                try:
                    new_process = watcher(timeout_ms=1000)
                    if new_process:
                        logger.info(f"Process created: {new_process.Name} (PID: {new_process.ProcessId})")
                        # Check for suspicious processes
                        self._check_process_suspicious(new_process)
                except Exception:
                    pass
                    
        except ImportError:
            logger.warning("WMI monitoring requires pywin32")
        except Exception as e:
            logger.error(f"Error in WMI monitoring: {e}")
    
    def _check_process_suspicious(self, process):
        """Check if process is suspicious"""
        suspicious_keywords = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'certutil']
        if any(keyword in process.Name.lower() for keyword in suspicious_keywords):
            logger.warning(f"Suspicious process: {process.Name} with command line: {process.CommandLine}")


if __name__ == "__main__":
    # Test the monitor
    def alert_callback(alert):
        print(f"ALERT: {alert['severity']} - {alert['title']}")
        print(f"Description: {alert['description']}")
        print(f"Category: {alert['category']}")
        print(f"Timestamp: {alert['timestamp']}")
        print("-" * 50)
    
    monitor = RealTimeMonitor(callback=alert_callback)
    monitor.start()
    
    try:
        print("Real-time monitoring started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
