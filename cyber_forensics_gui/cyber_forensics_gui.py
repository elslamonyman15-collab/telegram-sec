#!/usr/bin/env python3
"""
Cyber Forensics Toolkit v5.0 - Professional Edition
Production-ready GUI application for Windows security forensics
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import subprocess
import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
import re
import hashlib
import socket
import csv
from collections import defaultdict
import ipaddress
import math
import random
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Constants
APP_TITLE = "Cyber Forensics Toolkit v6.0 - Intelligence Edition"
APP_VERSION = "6.0.0"
LOG_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "Cyber_Forensic_Report")

# Severity levels
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

# Hacker/Intelligence theme colors
SEVERITY_COLORS = {
    SEVERITY_CRITICAL: "#FF0000",  # Classified red
    SEVERITY_HIGH: "#FF6600",      # Alert orange
    SEVERITY_MEDIUM: "#FFCC00",    # Warning yellow
    SEVERITY_LOW: "#00FF00",      # Matrix green
    SEVERITY_INFO: "#00FFFF"      # Cyber cyan
}

# Theme colors (default values)
COLOR_BACKGROUND = "#000000"      # Pure black
COLOR_PANEL = "#0a0a0a"           # Stealth gray
COLOR_ACCENT_PRIMARY = "#00FF00"  # Matrix green
COLOR_ACCENT_SECONDARY = "#00FFFF" # Cyber cyan
COLOR_CRITICAL = "#FF0000"         # Classified red
COLOR_GRID = "#1a1a1a"            # Grid lines
COLOR_TEXT = "#00FF00"            # Matrix green text
COLOR_TEXT_SECONDARY = "#00FFFF"  # Cyber cyan text

# Configuration file path
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".cyber_forensics_config.json")
TELEGRAM_CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".cyber_forensics_telegram_config.json")

# External URLs
URLS = {
    "virustotal": "https://www.virustotal.com/",
    "hybrid_analysis": "https://www.hybrid-analysis.com/",
    "mitre_attack": "https://attack.mitre.org/",
    "microsoft_security": "https://www.microsoft.com/en-us/security/",
    "cisa_alerts": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "haveibeenpwned": "https://haveibeenpwned.com/",
    "abuseipdb": "https://www.abuseipdb.com/",
    "cve_database": "https://cve.mitre.org/",
    "exploitdb": "https://www.exploit-db.com/",
    "threatconnect": "https://threatconnect.com/"
}

# Known malicious indicators
SUSPICIOUS_PORTS = ['4444', '5555', '6666', '31337', '12345', '54321', '1337', '8080', '8443']
SUSPICIOUS_PROCESS_NAMES = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32', 'certutil']
SUSPICIOUS_DOMAINS = ['malware', 'botnet', 'c2', 'command', 'update', 'download', 'suspicious', 'phishing', 'trojan', 'virus', 'payload', 'dropper', 'loader']
KNOWN_MALWARE_HASHES = set()  # Could be populated from threat intelligence feeds

# MITRE ATT&CK technique mappings
ATTACK_TECHNIQUES = {
    'process_injection': 'T1055',
    'scheduled_task': 'T1053',
    'registry_run_keys': 'T1063',
    'remote_services': 'T1021',
    'brute_force': 'T1110',
    'credential_dumping': 'T1003',
    'lateral_movement': 'T1021',
    'data_exfiltration': 'T1041'
}

# Telegram Bot Manager (lazy import to avoid dependency issues)
try:
    from telegram_bot import TelegramBotManager
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

# Real-time Monitoring (lazy import)
try:
    from realtime_monitor import RealTimeMonitor
    MONITOR_AVAILABLE = True
except ImportError:
    MONITOR_AVAILABLE = False

# AI Anomaly Detection (lazy import)
try:
    from ai_anomaly_detection import AnomalyDetector
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# External API Integration (lazy import)
try:
    from external_api import ThreatIntelligenceManager
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

# Memory Analysis (lazy import)
try:
    from memory_analysis import MemoryAnalyzer
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

# MFT Parser (lazy import)
try:
    from mft_parser import NTFSAnalyzer
    MFT_AVAILABLE = True
except ImportError:
    MFT_AVAILABLE = False


class CyberForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1600x1000")
        self.root.minsize(1400, 900)
        
        # Animation variables
        self.animation_running = True
        self.particles = []
        self.animation_frame = 0
        self.blink_state = True
        self.critical_alert_visible = False
        
        # Setup style
        self.setup_style()
        
        # Initialize variables
        self.scan_running = False
        self.scan_thread = None
        self.current_progress = 0
        self.total_steps = 12  # Updated for new forensic steps
        self.scan_data = {}
        self.threats = {severity: [] for severity in SEVERITY_COLORS.keys()}
        self.selected_scan_options = {
            'network': True,
            'process': True,
            'user': True,
            'persistence': True,
            'filesystem': True,
            'firewall': True,
            'events': True,
            'system': True,
            'registry': True,
            'memory': True,
            'artifacts': True,
            'eventlogs': True
        }
        
        # Initialize Telegram Bot
        self.telegram_bot = None
        if TELEGRAM_AVAILABLE:
            try:
                self.telegram_bot = TelegramBotManager(TELEGRAM_CONFIG_FILE)
                if self.telegram_bot.config.get("bot_token"):
                    self.telegram_bot.start_bot()
                    self.log_message("✓ Telegram Bot initialized successfully")
            except Exception as e:
                self.log_message(f"✗ Telegram Bot initialization failed: {e}")
        
        # Create animated background
        self.create_animated_background()
        
        # Create GUI
        self.create_main_layout()
        self.create_menu_bar()
        
        # Initialize log directory
        self.init_log_directory()
        
        # Load configuration
        self.load_config()
        
        # Start background animation
        self.animate_background()
        
        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()
        
    def setup_style(self):
        """Setup hacker/intelligence theme styling"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles with hacker theme colors
        self.style.configure('TFrame', background=COLOR_PANEL)
        self.style.configure('TNotebook', background=COLOR_PANEL)
        self.style.configure('TNotebook.Tab', padding=[12, 8], font=('Consolas', 10, 'bold'))
        self.style.configure('TLabel', background=COLOR_PANEL, foreground=COLOR_TEXT, font=('Consolas', 9))
        self.style.configure('TButton', font=('Consolas', 9, 'bold'), padding=8)
        self.style.configure('Header.TLabel', font=('Consolas', 14, 'bold'), foreground=COLOR_ACCENT_PRIMARY)
        self.style.configure('Critical.TLabel', foreground=COLOR_CRITICAL, font=('Consolas', 10, 'bold'))
        self.style.configure('High.TLabel', foreground=SEVERITY_COLORS[SEVERITY_HIGH], font=('Consolas', 10, 'bold'))
        self.style.configure('Medium.TLabel', foreground=SEVERITY_COLORS[SEVERITY_MEDIUM], font=('Consolas', 10, 'bold'))
        self.style.configure('Low.TLabel', foreground=SEVERITY_COLORS[SEVERITY_LOW], font=('Consolas', 10, 'bold'))
        self.style.configure('Info.TLabel', foreground=SEVERITY_COLORS[SEVERITY_INFO], font=('Consolas', 10, 'bold'))
        
        # Treeview style with hacker theme
        self.style.configure('Treeview', rowheight=28, font=('Consolas', 9), 
                           background=COLOR_PANEL, fieldbackground=COLOR_PANEL)
        self.style.configure('Treeview.Heading', font=('Consolas', 10, 'bold'), 
                           background=COLOR_GRID, foreground=COLOR_ACCENT_PRIMARY)
        self.style.map('Treeview', background=[('selected', COLOR_ACCENT_SECONDARY)], 
                      foreground=[('selected', COLOR_BACKGROUND)])
        
        # Progress bar style
        self.style.configure('TProgressbar', thickness=25, troughcolor=COLOR_GRID, background=COLOR_ACCENT_PRIMARY)
        
        # Checkbutton style
        self.style.configure('TCheckbutton', font=('Consolas', 9), background=COLOR_PANEL, foreground=COLOR_TEXT)
        
        self.root.configure(bg=COLOR_BACKGROUND)
        
    def create_animated_background(self):
        """Create animated background with hacker theme particles"""
        # Create canvas with black background
        self.bg_canvas = tk.Canvas(self.root, width=2000, height=1200, bg=COLOR_BACKGROUND, highlightthickness=0)
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.bg_canvas.tag_lower('all')
        
        # Initialize particles with hacker theme colors
        hacker_colors = [COLOR_ACCENT_PRIMARY, COLOR_ACCENT_SECONDARY, COLOR_CRITICAL, SEVERITY_COLORS[SEVERITY_HIGH]]
        for _ in range(50):
            self.particles.append({
                'x': random.random() * 2000,
                'y': random.random() * 1200,
                'vx': (random.random() - 0.5) * 2,
                'vy': (random.random() - 0.5) * 2,
                'size': random.random() * 3 + 1,
                'color': hacker_colors[int(random.random() * len(hacker_colors))]
            })
            
    def animate_background(self):
        """Animate background particles"""
        if not self.animation_running:
            return
            
        self.bg_canvas.delete('all')
        
        # Draw hacker grid background
        for i in range(0, 1200, 40):
            # Horizontal grid lines
            self.bg_canvas.create_line(0, i, 2000, i, fill=COLOR_GRID, width=1)
        for i in range(0, 2000, 40):
            # Vertical grid lines
            self.bg_canvas.create_line(i, 0, i, 1200, fill=COLOR_GRID, width=1)
            
        # Update and draw particles
        for particle in self.particles:
            particle['x'] += particle['vx']
            particle['y'] += particle['vy']
            
            # Bounce off edges
            if particle['x'] < 0 or particle['x'] > 2000:
                particle['vx'] *= -1
            if particle['y'] < 0 or particle['y'] > 1200:
                particle['vy'] *= -1
                
            # Draw particle with better visibility
            x, y = particle['x'], particle['y']
            size = particle['size']
            self.bg_canvas.create_oval(x - size, y - size, x + size, y + size, 
                                      fill=particle['color'], outline='')
            
        # Draw network lines between nearby particles
        for i, p1 in enumerate(self.particles):
            for p2 in self.particles[i+1:]:
                distance = math.sqrt((p1['x'] - p2['x'])**2 + (p1['y'] - p2['y'])**2)
                if distance < 150:
                    alpha = int(255 * (1 - distance / 150))
                    line_color = f'#{alpha:02x}{alpha:02x}{alpha:02x}'
                    self.bg_canvas.create_line(p1['x'], p1['y'], p2['x'], p2['y'], 
                                              fill=line_color, width=1)
        
        self.animation_frame += 1
        self.root.after(50, self.animate_background)
        
        # Blink critical alert if visible
        if self.critical_alert_visible:
            self.blink_critical_alert()
        
    def blink_critical_alert(self):
        """Blink the critical threat alert"""
        self.blink_state = not self.blink_state
        if self.blink_state:
            self.critical_alert_frame.config(bg='#ff0000')
            self.critical_alert_label.config(bg='#ff0000', fg='white')
        else:
            self.critical_alert_frame.config(bg='#8b0000')
            self.critical_alert_label.config(bg='#8b0000', fg='#ffff00')
        
    def show_critical_alert(self):
        """Show the critical threat alert banner"""
        if not self.critical_alert_visible:
            self.critical_alert_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
            self.critical_alert_visible = True
            self.log_message("⚠️ CRITICAL THREAT ALERT ACTIVATED - SYSTEM MAY BE COMPROMISED")
            self.play_alert_sound()
            
    def hide_critical_alert(self):
        """Hide the critical threat alert banner"""
        if self.critical_alert_visible:
            self.critical_alert_frame.pack_forget()
            self.critical_alert_visible = False
            
    def show_critical_alert_details(self, event=None):
        """Show detailed analysis of critical threats for non-technical users"""
        critical_threats = self.threats[SEVERITY_CRITICAL]
        
        if not critical_threats:
            messagebox.showinfo("Critical Alert", "No critical threats currently detected.")
            return
            
        # Create detailed explanation window
        detail_window = tk.Toplevel(self.root)
        detail_window.title("⚠️ CRITICAL THREAT ANALYSIS")
        detail_window.geometry("800x600")
        detail_window.configure(bg='#1a1a2e')
        
        # Header
        header_frame = tk.Frame(detail_window, bg='#ff0000', bd=2, relief=tk.RAISED)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = tk.Label(header_frame, text="⚠️ CRITICAL SECURITY THREAT DETECTED", 
                               font=('Segoe UI', 16, 'bold'), fg='white', bg='#ff0000')
        header_label.pack(pady=10)
        
        # Content frame
        content_frame = tk.Frame(detail_window, bg='#1a1a2e')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scrollable text area
        detail_text = scrolledtext.ScrolledText(content_frame, font=('Segoe UI', 10),
                                               bg='#0a0a1a', fg='white', wrap=tk.WORD,
                                               relief=tk.FLAT, bd=0)
        detail_text.pack(fill=tk.BOTH, expand=True)
        
        # Add user-friendly explanation
        detail_text.insert(tk.END, "=" * 70 + "\n")
        detail_text.insert(tk.END, "WHAT THIS MEANS FOR YOU:\n")
        detail_text.insert(tk.END, "=" * 70 + "\n\n")
        detail_text.insert(tk.END, "Your computer has detected a serious security threat that could put your\n")
        detail_text.insert(tk.END, "personal information and files at risk. This is NOT a false alarm.\n\n")
        
        detail_text.insert(tk.END, "=" * 70 + "\n")
        detail_text.insert(tk.END, "DETECTED THREATS:\n")
        detail_text.insert(tk.END, "=" * 70 + "\n\n")
        
        for i, threat in enumerate(critical_threats, 1):
            detail_text.insert(tk.END, f"THREAT #{i}:\n")
            detail_text.insert(tk.END, f"  What was found: {threat['title']}\n")
            detail_text.insert(tk.END, f"  Why it's dangerous: {threat['description']}\n")
            detail_text.insert(tk.END, f"  Where it was found: {threat['category']}\n")
            detail_text.insert(tk.END, f"  When it was detected: {threat['timestamp']}\n\n")
        
        detail_text.insert(tk.END, "=" * 70 + "\n")
        detail_text.insert(tk.END, "WHAT YOU SHOULD DO RIGHT NOW:\n")
        detail_text.insert(tk.END, "=" * 70 + "\n\n")
        detail_text.insert(tk.END, "1. DON'T PANIC - But take this seriously\n")
        detail_text.insert(tk.END, "2. DISCONNECT FROM INTERNET - Unplug your network cable or turn off WiFi\n")
        detail_text.insert(tk.END, "3. DON'T ENTER PASSWORDS - The threat might be stealing them\n")
        detail_text.insert(tk.END, "4. SAVE YOUR WORK - Backup important files to an external drive\n")
        detail_text.insert(tk.END, "5. CONTACT IT SUPPORT - If this is a work computer, call IT immediately\n")
        detail_text.insert(tk.END, "6. SCAN YOUR COMPUTER - Run a full antivirus scan\n")
        detail_text.insert(tk.END, "7. CHANGE PASSWORDS - After cleaning, change all your passwords\n\n")
        
        detail_text.insert(tk.END, "=" * 70 + "\n")
        detail_text.insert(tk.END, "IN SIMPLE TERMS:\n")
        detail_text.insert(tk.END, "=" * 70 + "\n\n")
        detail_text.insert(tk.END, "Think of this like finding a burglar in your house. You wouldn't ignore it.\n")
        detail_text.insert(tk.END, "These threats are like digital burglars trying to steal your information.\n")
        detail_text.insert(tk.END, "The good news is that we detected them early, so you can take action.\n\n")
        
        detail_text.insert(tk.END, "=" * 70 + "\n")
        detail_text.insert(tk.END, "NEED HELP?\n")
        detail_text.insert(tk.END, "=" * 70 + "\n\n")
        detail_text.insert(tk.END, "• If this is your personal computer: Contact a computer technician\n")
        detail_text.insert(tk.END, "• If this is a work computer: Contact your IT department immediately\n")
        detail_text.insert(tk.END, "• You can also export this report (File > Export PDF) to show to experts\n\n")
        
        detail_text.config(state=tk.DISABLED)
        
        # Action buttons
        button_frame = tk.Frame(detail_window, bg='#1a1a2e')
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        export_button = tk.Button(button_frame, text="📄 EXPORT REPORT", 
                                 command=lambda: [self.export_pdf(), detail_window.destroy()],
                                 font=('Segoe UI', 10, 'bold'), bg='#00aaff', fg='white',
                                 padx=15, pady=8, relief=tk.FLAT, cursor='hand2')
        export_button.pack(side=tk.LEFT, padx=5)
        
        close_button = tk.Button(button_frame, text="✕ CLOSE", 
                                command=detail_window.destroy,
                                font=('Segoe UI', 10, 'bold'), bg='#ff4444', fg='white',
                                padx=15, pady=8, relief=tk.FLAT, cursor='hand2')
        close_button.pack(side=tk.RIGHT, padx=5)
            
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for common actions"""
        self.root.bind('<Control-s>', lambda e: self.start_scan())
        self.root.bind('<Control-x>', lambda e: self.stop_scan())
        self.root.bind('<Control-e>', lambda e: self.export_json())
        self.root.bind('<Control-c>', lambda e: self.clear_results())
        self.root.bind('<F1>', lambda e: self.show_help())
        self.root.bind('<Escape>', lambda e: self.hide_critical_alert())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        
    def play_alert_sound(self):
        """Play alert sound for critical threats"""
        try:
            import winsound
            winsound.Beep(1000, 200)  # 1000Hz for 200ms
            winsound.Beep(800, 200)   # 800Hz for 200ms
            winsound.Beep(1000, 200)  # 1000Hz for 200ms
        except ImportError:
            pass  # Fallback silently if winsound not available
        except Exception:
            pass
        
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Report (PDF)", command=self.export_pdf)
        file_menu.add_command(label="Export Report (JSON)", command=self.export_json)
        file_menu.add_command(label="Export Report (CSV)", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Start Full Scan", command=self.start_scan)
        scan_menu.add_command(label="Stop Scan", command=self.stop_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Clear Results", command=self.clear_results)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Open Report Folder", command=self.open_report_folder)
        tools_menu.add_command(label="Compare with Previous Scan", command=self.compare_scans)
        tools_menu.add_separator()
        tools_menu.add_command(label="Telegram Bot Settings", command=self.open_telegram_settings)
        tools_menu.add_separator()
        tools_menu.add_command(label="Start Real-Time Monitoring", command=self.start_monitoring)
        tools_menu.add_command(label="Stop Real-Time Monitoring", command=self.stop_monitoring)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Theme Settings", command=self.open_theme_settings)
        view_menu.add_command(label="Reset to Default", command=self.reset_theme)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        
    def create_main_layout(self):
        """Create main application layout with hacker theme"""
        # Top control panel with hacker theme
        control_frame = tk.Frame(self.root, bg=COLOR_PANEL, bd=2, relief=tk.RAISED)
        control_frame.pack(fill=tk.X, side=tk.TOP, padx=10, pady=10)
        
        # Title with hacker theme
        title_frame = tk.Frame(control_frame, bg=COLOR_PANEL)
        title_frame.pack(side=tk.LEFT, padx=15)
        
        title_label = tk.Label(title_frame, text=APP_TITLE, font=('Consolas', 16, 'bold'), 
                               fg=COLOR_ACCENT_PRIMARY, bg=COLOR_PANEL)
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Advanced Threat Detection & Forensics", 
                                  font=('Consolas', 9), fg=COLOR_ACCENT_SECONDARY, bg=COLOR_PANEL)
        subtitle_label.pack()
        
        credit_label = tk.Label(title_frame, text="Created by Hasan Ibrahim", 
                               font=('Consolas', 8, 'italic'), fg=SEVERITY_COLORS[SEVERITY_HIGH], bg=COLOR_PANEL)
        credit_label.pack()
        
        # Control buttons with hacker theme
        button_frame = tk.Frame(control_frame, bg=COLOR_PANEL)
        button_frame.pack(side=tk.LEFT, padx=20)
        
        self.start_button = tk.Button(button_frame, text="▶ START SCAN", command=self.start_scan,
                                     font=('Consolas', 10, 'bold'), bg=COLOR_ACCENT_PRIMARY, fg=COLOR_BACKGROUND,
                                     padx=15, pady=8, relief=tk.FLAT, cursor='hand2')
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(button_frame, text="■ STOP", command=self.stop_scan, state=tk.DISABLED,
                                    font=('Consolas', 10, 'bold'), bg=COLOR_CRITICAL, fg='white',
                                    padx=15, pady=8, relief=tk.FLAT, cursor='hand2')
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = tk.Button(button_frame, text="📄 EXPORT", command=self.export_json,
                                      font=('Consolas', 10, 'bold'), bg=COLOR_ACCENT_SECONDARY, fg=COLOR_BACKGROUND,
                                      padx=15, pady=8, relief=tk.FLAT, cursor='hand2')
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(button_frame, text="🗑️ CLEAR", command=self.clear_results,
                                      font=('Consolas', 10, 'bold'), bg=SEVERITY_COLORS[SEVERITY_HIGH], fg='white',
                                      padx=15, pady=8, relief=tk.FLAT, cursor='hand2')
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Threat summary dashboard with hacker theme
        threat_frame = tk.Frame(control_frame, bg=COLOR_GRID, bd=2, relief=tk.RAISED)
        threat_frame.pack(side=tk.RIGHT, padx=10, pady=5)
        
        tk.Label(threat_frame, text="THREAT LEVEL", font=('Consolas', 8, 'bold'), 
                fg=COLOR_TEXT, bg=COLOR_GRID).pack(side=tk.TOP, pady=2)
        
        threat_inner = tk.Frame(threat_frame, bg=COLOR_GRID)
        threat_inner.pack(side=tk.TOP, padx=5, pady=2)
        
        self.critical_label = tk.Label(threat_inner, text="🔴 0", font=('Consolas', 12, 'bold'), 
                                      fg=COLOR_CRITICAL, bg=COLOR_GRID)
        self.critical_label.pack(side=tk.LEFT, padx=8)
        
        self.high_label = tk.Label(threat_inner, text="🟠 0", font=('Consolas', 12, 'bold'), 
                                   fg=SEVERITY_COLORS[SEVERITY_HIGH], bg=COLOR_GRID)
        self.high_label.pack(side=tk.LEFT, padx=8)
        
        self.medium_label = tk.Label(threat_inner, text="🟡 0", font=('Consolas', 12, 'bold'), 
                                     fg=SEVERITY_COLORS[SEVERITY_MEDIUM], bg=COLOR_GRID)
        self.medium_label.pack(side=tk.LEFT, padx=8)
        
        self.low_label = tk.Label(threat_inner, text="🟢 0", font=('Consolas', 12, 'bold'), 
                                  fg=SEVERITY_COLORS[SEVERITY_LOW], bg=COLOR_GRID)
        self.low_label.pack(side=tk.LEFT, padx=8)
        
        # Critical threat alert banner (hidden by default)
        self.critical_alert_frame = tk.Frame(control_frame, bg=COLOR_CRITICAL, bd=3, relief=tk.RAISED)
        self.critical_alert_label = tk.Label(self.critical_alert_frame, 
                                           text="⚠️ CRITICAL THREAT DETECTED - CLICK FOR DETAILS ⚠️",
                                           font=('Consolas', 14, 'bold'), fg='white', bg=COLOR_CRITICAL,
                                           cursor='hand2')
        self.critical_alert_label.pack(padx=20, pady=5)
        self.critical_alert_label.bind('<Button-1>', self.show_critical_alert_details)
        
        # Progress bar with hacker theme
        progress_frame = tk.Frame(self.root, bg=COLOR_PANEL, bd=2, relief=tk.SUNKEN)
        progress_frame.pack(fill=tk.X, side=tk.TOP, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, 
                                          style='TProgressbar')
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        self.progress_label = tk.Label(progress_frame, text="🔍 READY TO SCAN", font=('Consolas', 10, 'bold'),
                                     fg=COLOR_ACCENT_PRIMARY, bg=COLOR_PANEL)
        self.progress_label.pack(padx=10, pady=2)
        
        # Main content area with paned window
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Tabbed interface
        self.left_panel = ttk.Frame(self.paned_window)
        self.paned_window.add(self.left_panel, weight=3)
        
        self.notebook = ttk.Notebook(self.left_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_network_tab()
        self.create_process_tab()
        self.create_user_tab()
        self.create_persistence_tab()
        self.create_filesystem_tab()
        self.create_firewall_tab()
        self.create_eventlogs_tab()
        self.create_system_tab()
        
        # Right panel - Detail view with threat monitoring
        self.right_panel = ttk.Frame(self.paned_window, width=450)
        self.paned_window.add(self.right_panel, weight=1)
        
        self.create_threat_monitoring_panel()
        self.create_detail_panel()
        
        # Bottom log window with hacker theme
        log_frame = tk.Frame(self.root, bg=COLOR_PANEL, bd=2, relief=tk.RAISED)
        log_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=10)
        
        log_header = tk.Label(log_frame, text="📡 LIVE SCAN LOG", font=('Consolas', 10, 'bold'),
                            fg=COLOR_ACCENT_SECONDARY, bg=COLOR_PANEL)
        log_header.pack(side=tk.TOP, pady=2)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, font=('Consolas', 9), 
                                                   bg=COLOR_PANEL, fg=COLOR_ACCENT_PRIMARY, insertbackground='white',
                                                   relief=tk.FLAT, bd=0)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_threat_monitoring_panel(self):
        """Create real-time threat monitoring panel with tabs for each category"""
        threat_frame = tk.Frame(self.right_panel, bg=COLOR_PANEL, bd=2, relief=tk.RAISED)
        threat_frame.pack(fill=tk.X, padx=5, pady=5)
        
        threat_header = tk.Label(threat_frame, text="🚨 THREAT MONITOR", font=('Consolas', 11, 'bold'),
                                fg=COLOR_CRITICAL, bg=COLOR_PANEL)
        threat_header.pack(side=tk.TOP, pady=5)
        
        # Threat level indicator
        threat_level_frame = tk.Frame(threat_frame, bg=COLOR_GRID, bd=1, relief=tk.SUNKEN)
        threat_level_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.threat_level_label = tk.Label(threat_level_frame, text="SYSTEM STATUS: SECURE",
                                          font=('Consolas', 10, 'bold'), fg=COLOR_ACCENT_PRIMARY, bg=COLOR_GRID)
        self.threat_level_label.pack(pady=5)
        
        # Create notebook for threat categories
        self.threat_notebook = ttk.Notebook(threat_frame)
        self.threat_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs for each threat category
        self.threat_texts = {}
        categories = [
            ("Network", "network"),
            ("Process", "process"),
            ("User", "user"),
            ("Persistence", "persistence"),
            ("Filesystem", "filesystem"),
            ("Firewall", "firewall"),
            ("Event Logs", "eventlogs"),
            ("System", "system")
        ]
        
        for display_name, category in categories:
            tab = tk.Frame(self.threat_notebook, bg=COLOR_PANEL)
            self.threat_notebook.add(tab, text=display_name)
            
            threat_text = scrolledtext.ScrolledText(tab, font=('Consolas', 8),
                                                   bg=COLOR_PANEL, fg=COLOR_CRITICAL, wrap=tk.WORD,
                                                   relief=tk.FLAT, bd=0)
            threat_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
            threat_text.insert(tk.END, f"No {category.lower()} threats detected...")
            threat_text.config(state=tk.DISABLED)
            self.threat_texts[category] = threat_text
        
    def update_threat_monitor(self, severity, title, description, category="network"):
        """Update threat monitoring panel with new threat in category tab"""
        # Get the category-specific text widget
        if category in self.threat_texts:
            threat_text = self.threat_texts[category]
            threat_text.config(state=tk.NORMAL)
            
            # Add timestamp
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Format based on severity
            if severity == SEVERITY_CRITICAL:
                prefix = "🔴 CRITICAL"
                color = "#ff4444"
                self.threat_level_label.config(text="SYSTEM STATUS: COMPROMISED", fg='#ff4444')
            elif severity == SEVERITY_HIGH:
                prefix = "🟠 HIGH"
                color = "#ff8800"
                self.threat_level_label.config(text="SYSTEM STATUS: AT RISK", fg='#ff8800')
            elif severity == SEVERITY_MEDIUM:
                prefix = "🟡 MEDIUM"
                color = "#ffcc00"
            else:
                prefix = "🟢 LOW"
                color = "#00ff88"
                
            threat_text.insert(tk.END, f"[{timestamp}] {prefix}: {title}\n")
            threat_text.insert(tk.END, f"  {description}\n")
            threat_text.insert(tk.END, "-" * 40 + "\n")
            
            threat_text.see(tk.END)
            threat_text.config(state=tk.DISABLED)
        
    def create_detail_panel(self):
        """Create right detail panel with hacker theme"""
        detail_frame = tk.Frame(self.right_panel, bg=COLOR_PANEL, bd=2, relief=tk.RAISED)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        detail_header = tk.Label(detail_frame, text="🔍 FORENSIC ANALYSIS", font=('Consolas', 11, 'bold'),
                                fg=COLOR_ACCENT_PRIMARY, bg=COLOR_PANEL)
        detail_header.pack(side=tk.TOP, pady=5)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, font=('Consolas', 9),
                                                     bg=COLOR_PANEL, fg='white', wrap=tk.WORD,
                                                     relief=tk.FLAT, bd=0)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.detail_text.insert(tk.END, "══════════════════════════════════════════════════════════════\n")
        self.detail_text.insert(tk.END, "SELECT AN ITEM TO VIEW DETAILED FORENSIC ANALYSIS\n")
        self.detail_text.insert(tk.END, "══════════════════════════════════════════════════════════════\n")
        self.detail_text.config(state=tk.DISABLED)
        
        # Action buttons with hacker theme
        action_frame = tk.Frame(self.right_panel, bg=COLOR_PANEL)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        vt_button = tk.Button(action_frame, text="🔍 VIRUSTOTAL", command=self.search_virustotal,
                             font=('Consolas', 9, 'bold'), bg=COLOR_CRITICAL, fg='white',
                             padx=10, pady=5, relief=tk.FLAT, cursor='hand2')
        vt_button.pack(fill=tk.X, pady=2)
        
        browser_button = tk.Button(action_frame, text="🌐 OPEN BROWSER", command=self.open_in_browser,
                                   font=('Consolas', 9, 'bold'), bg=COLOR_ACCENT_SECONDARY, fg=COLOR_BACKGROUND,
                                   padx=10, pady=5, relief=tk.FLAT, cursor='hand2')
        browser_button.pack(fill=tk.X, pady=2)
        
        copy_button = tk.Button(action_frame, text="📋 COPY", command=self.copy_to_clipboard,
                               font=('Consolas', 9, 'bold'), bg=SEVERITY_COLORS[SEVERITY_HIGH], fg='white',
                               padx=10, pady=5, relief=tk.FLAT, cursor='hand2')
        copy_button.pack(fill=tk.X, pady=2)
        
        fp_button = tk.Button(action_frame, text="⚠️ FALSE POSITIVE", command=self.mark_false_positive,
                              font=('Consolas', 9, 'bold'), bg=SEVERITY_COLORS[SEVERITY_MEDIUM], fg=COLOR_BACKGROUND,
                              padx=10, pady=5, relief=tk.FLAT, cursor='hand2')
        fp_button.pack(fill=tk.X, pady=2)
        
    def create_network_tab(self):
        """Create Network Forensics tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 Network")
        
        # Create nested notebook for sub-tabs
        self.network_subnotebook = ttk.Notebook(tab)
        self.network_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Connections sub-tab
        connections_tab = ttk.Frame(self.network_subnotebook)
        self.network_subnotebook.add(connections_tab, text="Connections")
        
        columns = ("process", "local_addr", "remote_addr", "state", "severity")
        self.network_tree = ttk.Treeview(connections_tab, columns=columns, show='headings')
        self.network_tree.heading("process", text="Process")
        self.network_tree.heading("local_addr", text="Local Address")
        self.network_tree.heading("remote_addr", text="Remote Address")
        self.network_tree.heading("state", text="State")
        self.network_tree.heading("severity", text="Severity")
        self.network_tree.column("process", width=150)
        self.network_tree.column("local_addr", width=150)
        self.network_tree.column("remote_addr", width=150)
        self.network_tree.column("state", width=100)
        self.network_tree.column("severity", width=100)
        self.network_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.network_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("network"))
        self.network_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.network_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.network_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.network_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.network_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(connections_tab, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # DNS Cache sub-tab
        dns_tab = ttk.Frame(self.network_subnotebook)
        self.network_subnotebook.add(dns_tab, text="DNS Cache")
        
        dns_columns = ("name", "type", "ttl", "data")
        self.network_dns_tree = ttk.Treeview(dns_tab, columns=dns_columns, show='headings')
        self.network_dns_tree.heading("name", text="Domain Name")
        self.network_dns_tree.heading("type", text="Type")
        self.network_dns_tree.heading("ttl", text="TTL")
        self.network_dns_tree.heading("data", text="Data")
        self.network_dns_tree.column("name", width=300)
        self.network_dns_tree.column("type", width=100)
        self.network_dns_tree.column("ttl", width=80)
        self.network_dns_tree.column("data", width=300)
        self.network_dns_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.network_dns_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.network_dns_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.network_dns_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.network_dns_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.network_dns_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(dns_tab, orient=tk.VERTICAL, command=self.network_dns_tree.yview)
        self.network_dns_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Routing Table sub-tab
        routing_tab = ttk.Frame(self.network_subnotebook)
        self.network_subnotebook.add(routing_tab, text="Routing")
        
        routing_columns = ("destination", "mask", "gateway", "interface", "metric")
        self.network_routing_tree = ttk.Treeview(routing_tab, columns=routing_columns, show='headings')
        self.network_routing_tree.heading("destination", text="Destination")
        self.network_routing_tree.heading("mask", text="Netmask")
        self.network_routing_tree.heading("gateway", text="Gateway")
        self.network_routing_tree.heading("interface", text="Interface")
        self.network_routing_tree.heading("metric", text="Metric")
        self.network_routing_tree.column("destination", width=150)
        self.network_routing_tree.column("mask", width=150)
        self.network_routing_tree.column("gateway", width=150)
        self.network_routing_tree.column("interface", width=150)
        self.network_routing_tree.column("metric", width=80)
        self.network_routing_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.network_routing_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.network_routing_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.network_routing_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.network_routing_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.network_routing_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(routing_tab, orient=tk.VERTICAL, command=self.network_routing_tree.yview)
        self.network_routing_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_process_tab(self):
        """Create Process Anatomy tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚙️ Processes")
        
        # Create nested notebook for sub-tabs
        self.process_subnotebook = ttk.Notebook(tab)
        self.process_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Running Processes sub-tab
        running_tab = ttk.Frame(self.process_subnotebook)
        self.process_subnotebook.add(running_tab, text="Running")
        
        columns = ("name", "pid", "cpu", "memory", "path", "severity")
        self.process_tree = ttk.Treeview(running_tab, columns=columns, show='headings')
        self.process_tree.heading("name", text="Process Name")
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("cpu", text="CPU %")
        self.process_tree.heading("memory", text="Memory")
        self.process_tree.heading("path", text="Path")
        self.process_tree.heading("severity", text="Severity")
        self.process_tree.column("name", width=150)
        self.process_tree.column("pid", width=80)
        self.process_tree.column("cpu", width=80)
        self.process_tree.column("memory", width=100)
        self.process_tree.column("path", width=300)
        self.process_tree.column("severity", width=100)
        self.process_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.process_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("process"))
        self.process_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.process_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.process_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.process_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.process_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(running_tab, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # High CPU sub-tab
        high_cpu_tab = ttk.Frame(self.process_subnotebook)
        self.process_subnotebook.add(high_cpu_tab, text="High CPU")
        
        self.process_high_cpu_tree = ttk.Treeview(high_cpu_tab, columns=columns, show='headings')
        self.process_high_cpu_tree.heading("name", text="Process Name")
        self.process_high_cpu_tree.heading("pid", text="PID")
        self.process_high_cpu_tree.heading("cpu", text="CPU %")
        self.process_high_cpu_tree.heading("memory", text="Memory")
        self.process_high_cpu_tree.heading("path", text="Path")
        self.process_high_cpu_tree.heading("severity", text="Severity")
        self.process_high_cpu_tree.column("name", width=150)
        self.process_high_cpu_tree.column("pid", width=80)
        self.process_high_cpu_tree.column("cpu", width=80)
        self.process_high_cpu_tree.column("memory", width=100)
        self.process_high_cpu_tree.column("path", width=300)
        self.process_high_cpu_tree.column("severity", width=100)
        self.process_high_cpu_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.process_high_cpu_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.process_high_cpu_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.process_high_cpu_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.process_high_cpu_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.process_high_cpu_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(high_cpu_tab, orient=tk.VERTICAL, command=self.process_high_cpu_tree.yview)
        self.process_high_cpu_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # DLL Analysis sub-tab
        dll_tab = ttk.Frame(self.process_subnotebook)
        self.process_subnotebook.add(dll_tab, text="DLLs")
        
        dll_columns = ("process", "dll", "path", "severity")
        self.process_dll_tree = ttk.Treeview(dll_tab, columns=dll_columns, show='headings')
        self.process_dll_tree.heading("process", text="Process")
        self.process_dll_tree.heading("dll", text="DLL Name")
        self.process_dll_tree.heading("path", text="Path")
        self.process_dll_tree.heading("severity", text="Severity")
        self.process_dll_tree.column("process", width=150)
        self.process_dll_tree.column("dll", width=200)
        self.process_dll_tree.column("path", width=300)
        self.process_dll_tree.column("severity", width=100)
        self.process_dll_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.process_dll_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.process_dll_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.process_dll_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.process_dll_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.process_dll_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(dll_tab, orient=tk.VERTICAL, command=self.process_dll_tree.yview)
        self.process_dll_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_user_tab(self):
        """Create User Discovery tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="👤 Users")
        
        # Create nested notebook for sub-tabs
        self.user_subnotebook = ttk.Notebook(tab)
        self.user_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Local Users sub-tab
        local_tab = ttk.Frame(self.user_subnotebook)
        self.user_subnotebook.add(local_tab, text="Local Users")
        
        columns = ("name", "enabled", "password", "last_logon", "admin", "severity")
        self.user_tree = ttk.Treeview(local_tab, columns=columns, show='headings')
        self.user_tree.heading("name", text="Username")
        self.user_tree.heading("enabled", text="Enabled")
        self.user_tree.heading("password", text="Password")
        self.user_tree.heading("last_logon", text="Last Logon")
        self.user_tree.heading("admin", text="Admin")
        self.user_tree.heading("severity", text="Severity")
        self.user_tree.column("name", width=150)
        self.user_tree.column("enabled", width=80)
        self.user_tree.column("password", width=100)
        self.user_tree.column("last_logon", width=150)
        self.user_tree.column("admin", width=80)
        self.user_tree.column("severity", width=100)
        self.user_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.user_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("user"))
        self.user_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.user_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.user_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.user_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.user_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(local_tab, orient=tk.VERTICAL, command=self.user_tree.yview)
        self.user_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Admin Group sub-tab
        admin_tab = ttk.Frame(self.user_subnotebook)
        self.user_subnotebook.add(admin_tab, text="Admins")
        
        admin_columns = ("username", "group", "privileges", "severity")
        self.user_admin_tree = ttk.Treeview(admin_tab, columns=admin_columns, show='headings')
        self.user_admin_tree.heading("username", text="Username")
        self.user_admin_tree.heading("group", text="Group")
        self.user_admin_tree.heading("privileges", text="Privileges")
        self.user_admin_tree.heading("severity", text="Severity")
        self.user_admin_tree.column("username", width=150)
        self.user_admin_tree.column("group", width=150)
        self.user_admin_tree.column("privileges", width=300)
        self.user_admin_tree.column("severity", width=100)
        self.user_admin_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.user_admin_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.user_admin_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.user_admin_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.user_admin_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.user_admin_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(admin_tab, orient=tk.VERTICAL, command=self.user_admin_tree.yview)
        self.user_admin_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # User Privileges sub-tab
        priv_tab = ttk.Frame(self.user_subnotebook)
        self.user_subnotebook.add(priv_tab, text="Privileges")
        
        self.user_priv_tree = ttk.Treeview(priv_tab, columns=admin_columns, show='headings')
        self.user_priv_tree.heading("username", text="Username")
        self.user_priv_tree.heading("group", text="Group")
        self.user_priv_tree.heading("privileges", text="Privileges")
        self.user_priv_tree.heading("severity", text="Severity")
        self.user_priv_tree.column("username", width=150)
        self.user_priv_tree.column("group", width=150)
        self.user_priv_tree.column("privileges", width=300)
        self.user_priv_tree.column("severity", width=100)
        self.user_priv_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.user_priv_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.user_priv_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.user_priv_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.user_priv_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.user_priv_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(priv_tab, orient=tk.VERTICAL, command=self.user_priv_tree.yview)
        self.user_priv_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_persistence_tab(self):
        """Create Persistence Hunting tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔄 Persistence")
        
        # Create nested notebook for sub-tabs
        self.persistence_subnotebook = ttk.Notebook(tab)
        self.persistence_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Registry sub-tab
        registry_tab = ttk.Frame(self.persistence_subnotebook)
        self.persistence_subnotebook.add(registry_tab, text="Registry")
        
        columns = ("type", "name", "location", "value", "severity")
        self.persistence_tree = ttk.Treeview(registry_tab, columns=columns, show='headings')
        self.persistence_tree.heading("type", text="Type")
        self.persistence_tree.heading("name", text="Name")
        self.persistence_tree.heading("location", text="Location")
        self.persistence_tree.heading("value", text="Value")
        self.persistence_tree.heading("severity", text="Severity")
        self.persistence_tree.column("type", width=120)
        self.persistence_tree.column("name", width=200)
        self.persistence_tree.column("location", width=250)
        self.persistence_tree.column("value", width=300)
        self.persistence_tree.column("severity", width=100)
        self.persistence_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.persistence_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("persistence"))
        self.persistence_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.persistence_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.persistence_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.persistence_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.persistence_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(registry_tab, orient=tk.VERTICAL, command=self.persistence_tree.yview)
        self.persistence_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Scheduled Tasks sub-tab
        tasks_tab = ttk.Frame(self.persistence_subnotebook)
        self.persistence_subnotebook.add(tasks_tab, text="Tasks")
        
        task_columns = ("type", "name", "location", "value", "severity")
        self.persistence_tasks_tree = ttk.Treeview(tasks_tab, columns=task_columns, show='headings')
        self.persistence_tasks_tree.heading("type", text="Type")
        self.persistence_tasks_tree.heading("name", text="Name")
        self.persistence_tasks_tree.heading("location", text="Location")
        self.persistence_tasks_tree.heading("value", text="Value")
        self.persistence_tasks_tree.heading("severity", text="Severity")
        self.persistence_tasks_tree.column("type", width=120)
        self.persistence_tasks_tree.column("name", width=200)
        self.persistence_tasks_tree.column("location", width=250)
        self.persistence_tasks_tree.column("value", width=300)
        self.persistence_tasks_tree.column("severity", width=100)
        self.persistence_tasks_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.persistence_tasks_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.persistence_tasks_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.persistence_tasks_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.persistence_tasks_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.persistence_tasks_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(tasks_tab, orient=tk.VERTICAL, command=self.persistence_tasks_tree.yview)
        self.persistence_tasks_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Services sub-tab
        services_tab = ttk.Frame(self.persistence_subnotebook)
        self.persistence_subnotebook.add(services_tab, text="Services")
        
        self.persistence_services_tree = ttk.Treeview(services_tab, columns=task_columns, show='headings')
        self.persistence_services_tree.heading("type", text="Type")
        self.persistence_services_tree.heading("name", text="Name")
        self.persistence_services_tree.heading("location", text="Location")
        self.persistence_services_tree.heading("value", text="Value")
        self.persistence_services_tree.heading("severity", text="Severity")
        self.persistence_services_tree.column("type", width=120)
        self.persistence_services_tree.column("name", width=200)
        self.persistence_services_tree.column("location", width=250)
        self.persistence_services_tree.column("value", width=300)
        self.persistence_services_tree.column("severity", width=100)
        self.persistence_services_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.persistence_services_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.persistence_services_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.persistence_services_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.persistence_services_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.persistence_services_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(services_tab, orient=tk.VERTICAL, command=self.persistence_services_tree.yview)
        self.persistence_services_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Startup sub-tab
        startup_tab = ttk.Frame(self.persistence_subnotebook)
        self.persistence_subnotebook.add(startup_tab, text="Startup")
        
        self.persistence_startup_tree = ttk.Treeview(startup_tab, columns=task_columns, show='headings')
        self.persistence_startup_tree.heading("type", text="Type")
        self.persistence_startup_tree.heading("name", text="Name")
        self.persistence_startup_tree.heading("location", text="Location")
        self.persistence_startup_tree.heading("value", text="Value")
        self.persistence_startup_tree.heading("severity", text="Severity")
        self.persistence_startup_tree.column("type", width=120)
        self.persistence_startup_tree.column("name", width=200)
        self.persistence_startup_tree.column("location", width=250)
        self.persistence_startup_tree.column("value", width=300)
        self.persistence_startup_tree.column("severity", width=100)
        self.persistence_startup_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.persistence_startup_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.persistence_startup_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.persistence_startup_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.persistence_startup_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.persistence_startup_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar4 = ttk.Scrollbar(startup_tab, orient=tk.VERTICAL, command=self.persistence_startup_tree.yview)
        self.persistence_startup_tree.configure(yscroll=scrollbar4.set)
        scrollbar4.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_filesystem_tab(self):
        """Create File System Forensics tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📁 Files")
        
        # Create nested notebook for sub-tabs
        self.filesystem_subnotebook = ttk.Notebook(tab)
        self.filesystem_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Suspicious Files sub-tab
        suspicious_tab = ttk.Frame(self.filesystem_subnotebook)
        self.filesystem_subnotebook.add(suspicious_tab, text="Suspicious")
        
        columns = ("name", "path", "size", "modified", "hash", "severity")
        self.filesystem_tree = ttk.Treeview(suspicious_tab, columns=columns, show='headings')
        self.filesystem_tree.heading("name", text="File Name")
        self.filesystem_tree.heading("path", text="Full Path")
        self.filesystem_tree.heading("size", text="Size")
        self.filesystem_tree.heading("modified", text="Modified")
        self.filesystem_tree.heading("hash", text="SHA256")
        self.filesystem_tree.heading("severity", text="Severity")
        self.filesystem_tree.column("name", width=150)
        self.filesystem_tree.column("path", width=300)
        self.filesystem_tree.column("size", width=100)
        self.filesystem_tree.column("modified", width=150)
        self.filesystem_tree.column("hash", width=100)
        self.filesystem_tree.column("severity", width=100)
        self.filesystem_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.filesystem_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("filesystem"))
        self.filesystem_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.filesystem_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.filesystem_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.filesystem_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.filesystem_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(suspicious_tab, orient=tk.VERTICAL, command=self.filesystem_tree.yview)
        self.filesystem_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Recently Modified sub-tab
        recent_tab = ttk.Frame(self.filesystem_subnotebook)
        self.filesystem_subnotebook.add(recent_tab, text="Recent")
        
        self.filesystem_recent_tree = ttk.Treeview(recent_tab, columns=columns, show='headings')
        self.filesystem_recent_tree.heading("name", text="File Name")
        self.filesystem_recent_tree.heading("path", text="Full Path")
        self.filesystem_recent_tree.heading("size", text="Size")
        self.filesystem_recent_tree.heading("modified", text="Modified")
        self.filesystem_recent_tree.heading("hash", text="SHA256")
        self.filesystem_recent_tree.heading("severity", text="Severity")
        self.filesystem_recent_tree.column("name", width=150)
        self.filesystem_recent_tree.column("path", width=300)
        self.filesystem_recent_tree.column("size", width=100)
        self.filesystem_recent_tree.column("modified", width=150)
        self.filesystem_recent_tree.column("hash", width=100)
        self.filesystem_recent_tree.column("severity", width=100)
        self.filesystem_recent_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.filesystem_recent_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.filesystem_recent_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.filesystem_recent_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.filesystem_recent_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.filesystem_recent_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(recent_tab, orient=tk.VERTICAL, command=self.filesystem_recent_tree.yview)
        self.filesystem_recent_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # System Files sub-tab
        system_tab = ttk.Frame(self.filesystem_subnotebook)
        self.filesystem_subnotebook.add(system_tab, text="System")
        
        self.filesystem_system_tree = ttk.Treeview(system_tab, columns=columns, show='headings')
        self.filesystem_system_tree.heading("name", text="File Name")
        self.filesystem_system_tree.heading("path", text="Full Path")
        self.filesystem_system_tree.heading("size", text="Size")
        self.filesystem_system_tree.heading("modified", text="Modified")
        self.filesystem_system_tree.heading("hash", text="SHA256")
        self.filesystem_system_tree.heading("severity", text="Severity")
        self.filesystem_system_tree.column("name", width=150)
        self.filesystem_system_tree.column("path", width=300)
        self.filesystem_system_tree.column("size", width=100)
        self.filesystem_system_tree.column("modified", width=150)
        self.filesystem_system_tree.column("hash", width=100)
        self.filesystem_system_tree.column("severity", width=100)
        self.filesystem_system_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.filesystem_system_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.filesystem_system_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.filesystem_system_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.filesystem_system_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.filesystem_system_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(system_tab, orient=tk.VERTICAL, command=self.filesystem_system_tree.yview)
        self.filesystem_system_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
        # User Files sub-tab
        user_tab = ttk.Frame(self.filesystem_subnotebook)
        self.filesystem_subnotebook.add(user_tab, text="User")
        
        self.filesystem_user_tree = ttk.Treeview(user_tab, columns=columns, show='headings')
        self.filesystem_user_tree.heading("name", text="File Name")
        self.filesystem_user_tree.heading("path", text="Full Path")
        self.filesystem_user_tree.heading("size", text="Size")
        self.filesystem_user_tree.heading("modified", text="Modified")
        self.filesystem_user_tree.heading("hash", text="SHA256")
        self.filesystem_user_tree.heading("severity", text="Severity")
        self.filesystem_user_tree.column("name", width=150)
        self.filesystem_user_tree.column("path", width=300)
        self.filesystem_user_tree.column("size", width=100)
        self.filesystem_user_tree.column("modified", width=150)
        self.filesystem_user_tree.column("hash", width=100)
        self.filesystem_user_tree.column("severity", width=100)
        self.filesystem_user_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.filesystem_user_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.filesystem_user_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.filesystem_user_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.filesystem_user_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.filesystem_user_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar4 = ttk.Scrollbar(user_tab, orient=tk.VERTICAL, command=self.filesystem_user_tree.yview)
        self.filesystem_user_tree.configure(yscroll=scrollbar4.set)
        scrollbar4.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_firewall_tab(self):
        """Create Firewall & Hosts tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔥 Firewall")
        
        # Create nested notebook for sub-tabs
        self.firewall_subnotebook = ttk.Notebook(tab)
        self.firewall_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Firewall Rules sub-tab
        rules_tab = ttk.Frame(self.firewall_subnotebook)
        self.firewall_subnotebook.add(rules_tab, text="Rules")
        
        columns = ("type", "name", "direction", "action", "protocol", "ports", "severity")
        self.firewall_tree = ttk.Treeview(rules_tab, columns=columns, show='headings')
        self.firewall_tree.heading("type", text="Type")
        self.firewall_tree.heading("name", text="Rule Name")
        self.firewall_tree.heading("direction", text="Direction")
        self.firewall_tree.heading("action", text="Action")
        self.firewall_tree.heading("protocol", text="Protocol")
        self.firewall_tree.heading("ports", text="Ports")
        self.firewall_tree.heading("severity", text="Severity")
        self.firewall_tree.column("type", width=100)
        self.firewall_tree.column("name", width=200)
        self.firewall_tree.column("direction", width=100)
        self.firewall_tree.column("action", width=100)
        self.firewall_tree.column("protocol", width=100)
        self.firewall_tree.column("ports", width=100)
        self.firewall_tree.column("severity", width=100)
        self.firewall_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.firewall_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("firewall"))
        self.firewall_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.firewall_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.firewall_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.firewall_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.firewall_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(rules_tab, orient=tk.VERTICAL, command=self.firewall_tree.yview)
        self.firewall_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Hosts File sub-tab
        hosts_tab = ttk.Frame(self.firewall_subnotebook)
        self.firewall_subnotebook.add(hosts_tab, text="Hosts")
        
        hosts_columns = ("type", "name", "direction", "action", "protocol", "ports", "severity")
        self.firewall_hosts_tree = ttk.Treeview(hosts_tab, columns=hosts_columns, show='headings')
        self.firewall_hosts_tree.heading("type", text="Type")
        self.firewall_hosts_tree.heading("name", text="Name")
        self.firewall_hosts_tree.heading("direction", text="Direction")
        self.firewall_hosts_tree.heading("action", text="Action")
        self.firewall_hosts_tree.heading("protocol", text="Protocol")
        self.firewall_hosts_tree.heading("ports", text="Ports")
        self.firewall_hosts_tree.heading("severity", text="Severity")
        self.firewall_hosts_tree.column("type", width=100)
        self.firewall_hosts_tree.column("name", width=200)
        self.firewall_hosts_tree.column("direction", width=100)
        self.firewall_hosts_tree.column("action", width=100)
        self.firewall_hosts_tree.column("protocol", width=100)
        self.firewall_hosts_tree.column("ports", width=100)
        self.firewall_hosts_tree.column("severity", width=100)
        self.firewall_hosts_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.firewall_hosts_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.firewall_hosts_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.firewall_hosts_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.firewall_hosts_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.firewall_hosts_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(hosts_tab, orient=tk.VERTICAL, command=self.firewall_hosts_tree.yview)
        self.firewall_hosts_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Network Adapters sub-tab
        adapters_tab = ttk.Frame(self.firewall_subnotebook)
        self.firewall_subnotebook.add(adapters_tab, text="Adapters")
        
        adapter_columns = ("name", "status", "ip", "mac", "dns", "severity")
        self.firewall_adapters_tree = ttk.Treeview(adapters_tab, columns=adapter_columns, show='headings')
        self.firewall_adapters_tree.heading("name", text="Adapter")
        self.firewall_adapters_tree.heading("status", text="Status")
        self.firewall_adapters_tree.heading("ip", text="IP Address")
        self.firewall_adapters_tree.heading("mac", text="MAC Address")
        self.firewall_adapters_tree.heading("dns", text="DNS")
        self.firewall_adapters_tree.heading("severity", text="Severity")
        self.firewall_adapters_tree.column("name", width=150)
        self.firewall_adapters_tree.column("status", width=100)
        self.firewall_adapters_tree.column("ip", width=150)
        self.firewall_adapters_tree.column("mac", width=150)
        self.firewall_adapters_tree.column("dns", width=200)
        self.firewall_adapters_tree.column("severity", width=100)
        self.firewall_adapters_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.firewall_adapters_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.firewall_adapters_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.firewall_adapters_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.firewall_adapters_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.firewall_adapters_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(adapters_tab, orient=tk.VERTICAL, command=self.firewall_adapters_tree.yview)
        self.firewall_adapters_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_eventlogs_tab(self):
        """Create Security Event Logs tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📋 Event Logs")
        
        # Create nested notebook for sub-tabs
        self.eventlogs_subnotebook = ttk.Notebook(tab)
        self.eventlogs_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # Failed Logins sub-tab
        failed_tab = ttk.Frame(self.eventlogs_subnotebook)
        self.eventlogs_subnotebook.add(failed_tab, text="Failed Logins")
        
        columns = ("time", "event_id", "source", "message", "severity")
        self.eventlogs_tree = ttk.Treeview(failed_tab, columns=columns, show='headings')
        self.eventlogs_tree.heading("time", text="Time")
        self.eventlogs_tree.heading("event_id", text="Event ID")
        self.eventlogs_tree.heading("source", text="Source")
        self.eventlogs_tree.heading("message", text="Message")
        self.eventlogs_tree.heading("severity", text="Severity")
        self.eventlogs_tree.column("time", width=150)
        self.eventlogs_tree.column("event_id", width=80)
        self.eventlogs_tree.column("source", width=150)
        self.eventlogs_tree.column("message", width=400)
        self.eventlogs_tree.column("severity", width=100)
        self.eventlogs_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.eventlogs_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("eventlogs"))
        self.eventlogs_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.eventlogs_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.eventlogs_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.eventlogs_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.eventlogs_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(failed_tab, orient=tk.VERTICAL, command=self.eventlogs_tree.yview)
        self.eventlogs_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Successful Logins sub-tab
        success_tab = ttk.Frame(self.eventlogs_subnotebook)
        self.eventlogs_subnotebook.add(success_tab, text="Success Logins")
        
        self.eventlogs_success_tree = ttk.Treeview(success_tab, columns=columns, show='headings')
        self.eventlogs_success_tree.heading("time", text="Time")
        self.eventlogs_success_tree.heading("event_id", text="Event ID")
        self.eventlogs_success_tree.heading("source", text="Source")
        self.eventlogs_success_tree.heading("message", text="Message")
        self.eventlogs_success_tree.heading("severity", text="Severity")
        self.eventlogs_success_tree.column("time", width=150)
        self.eventlogs_success_tree.column("event_id", width=80)
        self.eventlogs_success_tree.column("source", width=150)
        self.eventlogs_success_tree.column("message", width=400)
        self.eventlogs_success_tree.column("severity", width=100)
        self.eventlogs_success_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.eventlogs_success_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.eventlogs_success_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.eventlogs_success_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.eventlogs_success_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.eventlogs_success_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(success_tab, orient=tk.VERTICAL, command=self.eventlogs_success_tree.yview)
        self.eventlogs_success_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Security Events sub-tab
        security_tab = ttk.Frame(self.eventlogs_subnotebook)
        self.eventlogs_subnotebook.add(security_tab, text="Security")
        
        self.eventlogs_security_tree = ttk.Treeview(security_tab, columns=columns, show='headings')
        self.eventlogs_security_tree.heading("time", text="Time")
        self.eventlogs_security_tree.heading("event_id", text="Event ID")
        self.eventlogs_security_tree.heading("source", text="Source")
        self.eventlogs_security_tree.heading("message", text="Message")
        self.eventlogs_security_tree.heading("severity", text="Severity")
        self.eventlogs_security_tree.column("time", width=150)
        self.eventlogs_security_tree.column("event_id", width=80)
        self.eventlogs_security_tree.column("source", width=150)
        self.eventlogs_security_tree.column("message", width=400)
        self.eventlogs_security_tree.column("severity", width=100)
        self.eventlogs_security_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.eventlogs_security_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.eventlogs_security_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.eventlogs_security_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.eventlogs_security_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.eventlogs_security_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(security_tab, orient=tk.VERTICAL, command=self.eventlogs_security_tree.yview)
        self.eventlogs_security_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
        # System Events sub-tab
        sys_events_tab = ttk.Frame(self.eventlogs_subnotebook)
        self.eventlogs_subnotebook.add(sys_events_tab, text="System")
        
        self.eventlogs_system_tree = ttk.Treeview(sys_events_tab, columns=columns, show='headings')
        self.eventlogs_system_tree.heading("time", text="Time")
        self.eventlogs_system_tree.heading("event_id", text="Event ID")
        self.eventlogs_system_tree.heading("source", text="Source")
        self.eventlogs_system_tree.heading("message", text="Message")
        self.eventlogs_system_tree.heading("severity", text="Severity")
        self.eventlogs_system_tree.column("time", width=150)
        self.eventlogs_system_tree.column("event_id", width=80)
        self.eventlogs_system_tree.column("source", width=150)
        self.eventlogs_system_tree.column("message", width=400)
        self.eventlogs_system_tree.column("severity", width=100)
        self.eventlogs_system_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.eventlogs_system_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.eventlogs_system_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.eventlogs_system_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.eventlogs_system_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.eventlogs_system_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar4 = ttk.Scrollbar(sys_events_tab, orient=tk.VERTICAL, command=self.eventlogs_system_tree.yview)
        self.eventlogs_system_tree.configure(yscroll=scrollbar4.set)
        scrollbar4.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Application Events sub-tab
        app_tab = ttk.Frame(self.eventlogs_subnotebook)
        self.eventlogs_subnotebook.add(app_tab, text="Application")
        
        self.eventlogs_app_tree = ttk.Treeview(app_tab, columns=columns, show='headings')
        self.eventlogs_app_tree.heading("time", text="Time")
        self.eventlogs_app_tree.heading("event_id", text="Event ID")
        self.eventlogs_app_tree.heading("source", text="Source")
        self.eventlogs_app_tree.heading("message", text="Message")
        self.eventlogs_app_tree.heading("severity", text="Severity")
        self.eventlogs_app_tree.column("time", width=150)
        self.eventlogs_app_tree.column("event_id", width=80)
        self.eventlogs_app_tree.column("source", width=150)
        self.eventlogs_app_tree.column("message", width=400)
        self.eventlogs_app_tree.column("severity", width=100)
        self.eventlogs_app_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.eventlogs_app_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.eventlogs_app_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.eventlogs_app_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.eventlogs_app_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.eventlogs_app_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar5 = ttk.Scrollbar(app_tab, orient=tk.VERTICAL, command=self.eventlogs_app_tree.yview)
        self.eventlogs_app_tree.configure(yscroll=scrollbar5.set)
        scrollbar5.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_system_tab(self):
        """Create System Integrity tab with sub-tabs"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="💻 System")
        
        # Create nested notebook for sub-tabs
        self.system_subnotebook = ttk.Notebook(tab)
        self.system_subnotebook.pack(fill=tk.BOTH, expand=True)
        
        # System Info sub-tab
        info_tab = ttk.Frame(self.system_subnotebook)
        self.system_subnotebook.add(info_tab, text="System Info")
        
        columns = ("category", "item", "value", "status", "severity")
        self.system_tree = ttk.Treeview(info_tab, columns=columns, show='headings')
        self.system_tree.heading("category", text="Category")
        self.system_tree.heading("item", text="Item")
        self.system_tree.heading("value", text="Value")
        self.system_tree.heading("status", text="Status")
        self.system_tree.heading("severity", text="Severity")
        self.system_tree.column("category", width=150)
        self.system_tree.column("item", width=200)
        self.system_tree.column("value", width=250)
        self.system_tree.column("status", width=100)
        self.system_tree.column("severity", width=100)
        self.system_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.system_tree.bind('<<TreeviewSelect>>', lambda e: self.show_item_details("system"))
        self.system_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.system_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.system_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.system_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.system_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar1 = ttk.Scrollbar(info_tab, orient=tk.VERTICAL, command=self.system_tree.yview)
        self.system_tree.configure(yscroll=scrollbar1.set)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Environment Variables sub-tab
        env_tab = ttk.Frame(self.system_subnotebook)
        self.system_subnotebook.add(env_tab, text="Environment")
        
        env_columns = ("name", "value", "severity")
        self.system_env_tree = ttk.Treeview(env_tab, columns=env_columns, show='headings')
        self.system_env_tree.heading("name", text="Variable Name")
        self.system_env_tree.heading("value", text="Value")
        self.system_env_tree.heading("severity", text="Severity")
        self.system_env_tree.column("name", width=200)
        self.system_env_tree.column("value", width=400)
        self.system_env_tree.column("severity", width=100)
        self.system_env_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.system_env_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.system_env_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.system_env_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.system_env_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.system_env_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar2 = ttk.Scrollbar(env_tab, orient=tk.VERTICAL, command=self.system_env_tree.yview)
        self.system_env_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Installed Software sub-tab
        software_tab = ttk.Frame(self.system_subnotebook)
        self.system_subnotebook.add(software_tab, text="Software")
        
        software_columns = ("name", "version", "publisher", "install_date", "severity")
        self.system_software_tree = ttk.Treeview(software_tab, columns=software_columns, show='headings')
        self.system_software_tree.heading("name", text="Software Name")
        self.system_software_tree.heading("version", text="Version")
        self.system_software_tree.heading("publisher", text="Publisher")
        self.system_software_tree.heading("install_date", text="Install Date")
        self.system_software_tree.heading("severity", text="Severity")
        self.system_software_tree.column("name", width=200)
        self.system_software_tree.column("version", width=100)
        self.system_software_tree.column("publisher", width=150)
        self.system_software_tree.column("install_date", width=150)
        self.system_software_tree.column("severity", width=100)
        self.system_software_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.system_software_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.system_software_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.system_software_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.system_software_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.system_software_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar3 = ttk.Scrollbar(software_tab, orient=tk.VERTICAL, command=self.system_software_tree.yview)
        self.system_software_tree.configure(yscroll=scrollbar3.set)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Patches/Updates sub-tab
        patches_tab = ttk.Frame(self.system_subnotebook)
        self.system_subnotebook.add(patches_tab, text="Patches")
        
        patch_columns = ("kb", "title", "installed", "severity")
        self.system_patches_tree = ttk.Treeview(patches_tab, columns=patch_columns, show='headings')
        self.system_patches_tree.heading("kb", text="KB Article")
        self.system_patches_tree.heading("title", text="Title")
        self.system_patches_tree.heading("installed", text="Installed")
        self.system_patches_tree.heading("severity", text="Severity")
        self.system_patches_tree.column("kb", width=100)
        self.system_patches_tree.column("title", width=400)
        self.system_patches_tree.column("installed", width=100)
        self.system_patches_tree.column("severity", width=100)
        self.system_patches_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.system_patches_tree.tag_configure('critical', background='#330000', foreground='#FF0000')
        self.system_patches_tree.tag_configure('high', background='#331a00', foreground='#FF6600')
        self.system_patches_tree.tag_configure('medium', background='#333300', foreground='#FFCC00')
        self.system_patches_tree.tag_configure('low', background='#002200', foreground='#00FF00')
        self.system_patches_tree.tag_configure('info', background='#001a33', foreground='#00FFFF')
        scrollbar4 = ttk.Scrollbar(patches_tab, orient=tk.VERTICAL, command=self.system_patches_tree.yview)
        self.system_patches_tree.configure(yscroll=scrollbar4.set)
        scrollbar4.pack(side=tk.RIGHT, fill=tk.Y)
        
    def init_log_directory(self):
        """Initialize log directory structure"""
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            
            # Create subdirectories
            subdirs = [
                "SUMMARY",
                "NETWORK_FORENSICS",
                "PROCESS_ANALYSIS",
                "USER_AUDIT",
                "PERSISTENCE",
                "FILE_SYSTEM",
                "FIREWALL_HOSTS",
                "EVENT_LOGS",
                "METADATA"
            ]
            
            for subdir in subdirs:
                os.makedirs(os.path.join(LOG_DIR, subdir), exist_ok=True)
                
            self.log_message(f"Log directory initialized: {LOG_DIR}")
        except Exception as e:
            self.log_message(f"Error initializing log directory: {str(e)}")
            
    def log_message(self, message):
        """Log message to the log window"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_progress(self, step, message):
        """Update progress bar and label"""
        self.current_progress = (step / self.total_steps) * 100
        self.progress_var.set(self.current_progress)
        self.progress_label.config(text=f"Step {step}/{self.total_steps}: {message}")
        self.root.update_idletasks()
        
    def start_scan(self):
        """Start the full security scan"""
        if self.scan_running:
            return
            
        self.scan_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.current_progress = 0
        
        # Clear previous results
        self.clear_results()
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(target=self.run_full_scan, daemon=True)
        self.scan_thread.start()
        
    def stop_scan(self):
        """Stop the running scan"""
        self.scan_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_message("Scan stopped by user")
        
    def run_full_scan(self):
        """Run the full security scan"""
        try:
            self.log_message("Starting full security scan...")
            
            # Step 1: Network Forensics
            if not self.scan_running:
                return
            self.update_progress(1, "Analyzing network connections and DNS cache...")
            self.scan_network_forensics()
            
            # Step 2: Process Anatomy
            if not self.scan_running:
                return
            self.update_progress(2, "Analyzing running processes and DLLs...")
            self.scan_process_anatomy()
            
            # Step 3: User Discovery
            if not self.scan_running:
                return
            self.update_progress(3, "Auditing user accounts and privileges...")
            self.scan_user_discovery()
            
            # Step 4: Persistence Hunting
            if not self.scan_running:
                return
            self.update_progress(4, "Scanning persistence mechanisms...")
            self.scan_persistence_hunting()
            
            # Step 5: File System Forensics
            if not self.scan_running:
                return
            self.update_progress(5, "Scanning file system for suspicious files...")
            self.scan_filesystem_forensics()
            
            # Step 6: Firewall & Hosts
            if not self.scan_running:
                return
            self.update_progress(6, "Auditing firewall rules and hosts file...")
            self.scan_firewall_hosts()
            
            # Step 7: Event Logs
            if not self.scan_running:
                return
            self.update_progress(7, "Analyzing security event logs...")
            self.scan_event_logs()
            
            # Step 8: System Integrity
            if not self.scan_running:
                return
            self.update_progress(8, "Performing system integrity check...")
            self.scan_system_integrity()
            
            # Complete
            self.progress_var.set(100)
            self.progress_label.config(text="Scan completed successfully")
            self.log_message("Full security scan completed!")
            
            # Update threat summary
            self.update_threat_summary()
            
            # Generate summary report
            self.generate_summary_report()
            
        except Exception as e:
            self.log_message(f"Error during scan: {str(e)}")
        finally:
            self.scan_running = False
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            
    def scan_network_forensics(self):
        """Scan network connections and DNS cache"""
        self.log_message("[Network] Gathering network evidence...")
        
        try:
            # Get network connections
            result = subprocess.run(['netstat', '-anob'], capture_output=True, text=True, timeout=60)
            connections = result.stdout
            
            # Save to file
            network_file = os.path.join(LOG_DIR, "NETWORK_FORENSICS", "Active_Connections.txt")
            with open(network_file, 'w') as f:
                f.write("=== FULL LIVE NETWORK ESTABLISHED CONNECTIONS ===\n")
                f.write(connections)
                
            # Parse and display in GUI
            self.parse_network_connections(connections)
            
            # Get DNS cache
            result = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=60)
            dns_cache = result.stdout
            
            dns_file = os.path.join(LOG_DIR, "NETWORK_FORENSICS", "DNS_Cache.txt")
            with open(dns_file, 'w') as f:
                f.write("=== DNS CACHE DUMP ===\n")
                f.write(dns_cache)
                
            self.parse_dns_cache(dns_cache)
            
            # Get routing table
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=60)
            route_table = result.stdout
            
            route_file = os.path.join(LOG_DIR, "NETWORK_FORENSICS", "Routing_Table.txt")
            with open(route_file, 'w') as f:
                f.write("=== IP ROUTING TABLE ===\n")
                f.write(route_table)
                
            self.parse_routing_table(route_table)
            
            self.log_message("[Network] Network evidence captured successfully")
            
        except subprocess.TimeoutExpired:
            self.log_message("[Network] Command timed out")
        except Exception as e:
            self.log_message(f"[Network] Error: {str(e)}")
            
    def parse_network_connections(self, data):
        """Parse network connections with professional-grade analysis"""
        lines = data.split('\n')
        connections = []
        current_process = None
        
        for line in lines:
            line = line.strip()
            
            # Extract process name from lines like "tcp        0      0 0.0.0.0:135  ..."
            if line and not line.startswith('Active') and not line.startswith('Proto') and not line.startswith('TCP') and not line.startswith('UDP'):
                if 'can be obtained' in line:
                    # Extract process name from "can be obtained" line
                    match = re.search(r'\[([^\]]+)\]', line)
                    if match:
                        current_process = match.group(1)
                elif ':' in line and ('.' in line or line.startswith('[')):
                    # Parse connection line
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            protocol = parts[0]
                            local_addr = parts[1]
                            remote_addr = parts[2] if len(parts) > 2 else "*:*"
                            state = parts[3] if len(parts) > 3 else "N/A"
                            
                            # Parse addresses
                            local_ip, local_port = self.parse_address(local_addr)
                            remote_ip, remote_port = self.parse_address(remote_addr)
                            
                            # Determine severity with advanced analysis
                            severity, threat_info = self.assess_network_severity_advanced(
                                protocol, local_ip, local_port, remote_ip, remote_port, state
                            )
                            
                            connection = {
                                'process': current_process or 'System',
                                'protocol': protocol or 'N/A',
                                'local_ip': local_ip or '*',
                                'local_port': local_port or '0',
                                'remote_ip': remote_ip or '*',
                                'remote_port': remote_port or '0',
                                'state': state or 'N/A',
                                'severity': severity,
                                'threat_info': threat_info
                            }
                            connections.append(connection)
                            
                            # Add formatted display with severity color tag
                            display_remote = f"{remote_ip}:{remote_port}" if remote_ip != "*" else "Listening"
                            severity_tag = severity.lower() if severity else 'info'
                            self.root.after(0, lambda conn=connection, tag=severity_tag: self.network_tree.insert('', tk.END, values=(
                                conn['process'],
                                f"{conn['local_ip']}:{conn['local_port']}",
                                display_remote,
                                conn['state'],
                                conn['severity']
                            ), tags=(tag,)))
                            
                            # Log high-severity findings
                            if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                                self.log_message(f"[NETWORK] {threat_info}")
                                self.add_threat(severity, "Suspicious Network Connection", 
                                              threat_info, "network")
                                
                        except Exception as e:
                            continue
                            
        # Save structured data
        self.scan_data['network_connections'] = connections
                    
    def parse_address(self, addr):
        """Parse IP address and port from address string"""
        if ':' in addr:
            parts = addr.rsplit(':', 1)
            ip = parts[0]
            port = parts[1] if len(parts) > 1 else "0"
            # Handle IPv6 addresses
            if ']' in ip:
                ip = ip.split(']')[0].replace('[', '')
            return ip, port
        return "*", "0"
        
    def assess_network_severity_advanced(self, protocol, local_ip, local_port, remote_ip, remote_port, state):
        """Advanced network threat assessment"""
        threat_info = []
        
        # Check for established connections to foreign IPs
        if state == "ESTABLISHED" and remote_ip != "*":
            try:
                ip_obj = ipaddress.ip_address(remote_ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    threat_info.append(f"Foreign connection to {remote_ip}")
                    # Check for known malicious countries/regions (simplified)
                    # In production, use GeoIP database
                    return SEVERITY_HIGH, f"Foreign IP connection: {remote_ip}:{remote_port} - Investigate at AbuseIPDB"
            except ValueError:
                pass
                
        # Check for suspicious ports
        if remote_port in SUSPICIOUS_PORTS:
            return SEVERITY_CRITICAL, f"Suspicious port {remote_port} - Common malware C2 port"
            
        if local_port in SUSPICIOUS_PORTS:
            return SEVERITY_HIGH, f"Listening on suspicious port {local_port} - Potential backdoor"
            
        # Check for non-standard listening ports
        if state == "LISTENING" and local_port not in ["80", "443", "22", "3389", "135", "139", "445", "53", "88", "445", "135"]:
            threat_info.append(f"Non-standard listening port: {local_port}")
            return SEVERITY_MEDIUM, f"Non-standard port {local_port} - Verify service legitimacy"
            
        # Check for connections to non-standard remote ports
        if state == "ESTABLISHED" and remote_port not in ["80", "443", "22", "3389", "53", "88", "445", "135", "139"]:
            threat_info.append(f"Connection to non-standard port: {remote_port}")
            return SEVERITY_MEDIUM, f"Non-standard remote port {remote_port} - Investigate service"
            
        # Check for multiple connections from same process (potential DDoS or scanning)
        # This would require tracking connection counts per process
        
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal network activity"
        
    def parse_dns_cache(self, data):
        """Parse DNS cache with advanced threat detection"""
        lines = data.split('\n')
        dns_entries = []
        current_entry = {}
        
        for line in lines:
            line = line.strip()
            
            # Parse DNS cache entries
            if line.startswith('Record Name') or line.startswith('-'):
                if current_entry:
                    dns_entries.append(current_entry)
                    current_entry = {}
                    
            if 'Record Name' in line:
                current_entry['name'] = line.split(':', 1)[1].strip()
            elif 'Record Type' in line:
                current_entry['type'] = line.split(':', 1)[1].strip()
            elif 'Time To Live' in line:
                current_entry['ttl'] = line.split(':', 1)[1].strip()
            elif 'Data Length' in line:
                current_entry['data_length'] = line.split(':', 1)[1].strip()
            elif 'Section' in line:
                current_entry['section'] = line.split(':', 1)[1].strip()
                
        # Add last entry
        if current_entry:
            dns_entries.append(current_entry)
            
        # Analyze each entry and populate treeview
        for entry in dns_entries:
            if 'name' in entry:
                domain = entry['name'].lower()
                severity = SEVERITY_INFO
                threat_info = "Normal DNS entry"
                
                # Check for suspicious domains
                for suspicious in SUSPICIOUS_DOMAINS:
                    if suspicious in domain:
                        threat_msg = f"Suspicious DNS domain: {entry['name']} - Contains '{suspicious}'"
                        self.log_message(f"[DNS] {threat_msg}")
                        self.add_threat(SEVERITY_CRITICAL, "Suspicious DNS Entry", threat_msg, "network")
                        severity = SEVERITY_CRITICAL
                        threat_info = threat_msg
                        
                # Check for newly registered domains (TTL analysis)
                if 'ttl' in entry:
                    try:
                        ttl = int(entry['ttl'])
                        if ttl < 300:  # Very low TTL could indicate fast-flux or DGA
                            threat_msg = f"Low TTL DNS entry: {entry['name']} (TTL: {ttl}s) - Possible fast-flux"
                            self.log_message(f"[DNS] {threat_msg}")
                            self.add_threat(SEVERITY_HIGH, "Low TTL DNS Entry", threat_msg, "network")
                            if severity == SEVERITY_INFO:
                                severity = SEVERITY_HIGH
                                threat_info = threat_msg
                    except ValueError:
                        pass
                        
                # Check for non-standard TLDs
                if 'name' in entry:
                    tld = entry['name'].split('.')[-1] if '.' in entry['name'] else ''
                    if tld and tld not in ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'local']:
                        # Could be legitimate but worth flagging
                        pass
                
                # Add to DNS treeview with severity tag
                severity_tag = severity.lower() if severity else 'info'
                self.root.after(0, lambda e=entry, tag=severity_tag: self.network_dns_tree.insert('', tk.END, values=(
                    e.get('name', 'N/A'),
                    e.get('type', 'N/A'),
                    e.get('ttl', 'N/A'),
                    e.get('data_length', 'N/A')
                ), tags=(tag,)))
                        
        self.scan_data['dns_cache'] = dns_entries
                    
    def parse_routing_table(self, data):
        """Parse routing table and populate treeview"""
        lines = data.split('\n')
        routes = []
        in_route_section = False
        
        for line in lines:
            line = line.strip()
            
            # Look for route table section
            if 'IPv4 Route Table' in line or 'Route Table' in line:
                in_route_section = True
                continue
                
            if in_route_section and line and not line.startswith('==='):
                # Parse route entries
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        destination = parts[0] if parts[0] != '0.0.0.0' else 'Default Route'
                        mask = parts[1] if len(parts) > 1 else 'N/A'
                        gateway = parts[2] if len(parts) > 2 else 'N/A'
                        interface = parts[3] if len(parts) > 3 else 'N/A'
                        metric = parts[4] if len(parts) > 4 else 'N/A'
                        
                        # Assess severity
                        severity = SEVERITY_INFO
                        if gateway != '0.0.0.0' and gateway != 'N/A':
                            # Check for suspicious gateways
                            try:
                                ip_obj = ipaddress.ip_address(gateway)
                                if not ip_obj.is_private and not ip_obj.is_loopback:
                                    severity = SEVERITY_HIGH
                            except ValueError:
                                pass
                        
                        # Add to routing treeview with severity tag
                        severity_tag = severity.lower() if severity else 'info'
                        self.root.after(0, lambda d=destination, m=mask, g=gateway, i=interface, me=metric, tag=severity_tag: 
                            self.network_routing_tree.insert('', tk.END, values=(
                                d, m, g, i, me
                            ), tags=(tag,)))
                            
                        routes.append({
                            'destination': destination,
                            'mask': mask,
                            'gateway': gateway,
                            'interface': interface,
                            'metric': metric,
                            'severity': severity
                        })
                    except Exception as e:
                        continue
                        
        self.scan_data['routing_table'] = routes
                    
    def scan_process_anatomy(self):
        """Scan running processes and DLLs"""
        self.log_message("[Process] Analyzing processes...")
        
        try:
            # Get process list using PowerShell
            ps_command = "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                processes = json.loads(result.stdout)
                
                # Save to file
                process_file = os.path.join(LOG_DIR, "PROCESS_ANALYSIS", "Process_List.txt")
                with open(process_file, 'w') as f:
                    f.write("=== PROCESS LIST ===\n")
                    f.write(json.dumps(processes, indent=2))
                    
                # Parse and display
                self.parse_processes(processes)
                
            # Get high CPU processes
            ps_command = "Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id, ProcessName, CPU, WorkingSet, Path | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                high_cpu = json.loads(result.stdout)
                high_cpu_file = os.path.join(LOG_DIR, "PROCESS_ANALYSIS", "High_CPU_Processes.txt")
                with open(high_cpu_file, 'w') as f:
                    f.write("=== HIGH CPU PROCESSES ===\n")
                    f.write(json.dumps(high_cpu, indent=2))
                    
            self.log_message("[Process] Process analysis completed")
            
        except subprocess.TimeoutExpired:
            self.log_message("[Process] Command timed out")
        except Exception as e:
            self.log_message(f"[Process] Error: {str(e)}")
            
    def parse_processes(self, processes):
        """Parse process list with advanced threat analysis"""
        if not isinstance(processes, list):
            processes = [processes]
            
        analyzed_processes = []
        
        for proc in processes:
            try:
                pid = proc.get('ProcessId', 'N/A')
                name = proc.get('Name', 'N/A')
                command_line = proc.get('CommandLine', 'N/A')
                path = proc.get('ExecutablePath', 'N/A')
                parent_pid = proc.get('ParentProcessId', 'N/A')
                
                # Advanced severity assessment
                severity, threat_info = self.assess_process_severity_advanced(name, path, command_line, pid)
                
                process_data = {
                    'name': name or 'N/A',
                    'pid': pid or 'N/A',
                    'parent_pid': parent_pid or 'N/A',
                    'command_line': command_line or 'N/A',
                    'path': path or 'N/A',
                    'severity': severity,
                    'threat_info': threat_info
                }
                analyzed_processes.append(process_data)
                
                # Add to GUI with formatted data and severity color tag
                severity_tag = severity.lower() if severity else 'info'
                self.root.after(0, lambda p=process_data, tag=severity_tag: self.process_tree.insert('', tk.END, values=(
                    p['name'],
                    p['pid'],
                    'N/A',  # CPU - would need additional query
                    'N/A',  # Memory - would need additional query
                    (p['path'][:80] + '...' if p['path'] and len(p['path']) > 80 else p['path'] or 'N/A'),
                    p['severity']
                ), tags=(tag,)))
                
                # Log high-severity findings
                if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                    self.log_message(f"[PROCESS] {threat_info}")
                    self.add_threat(severity, "Suspicious Process", threat_info, "process")
                    
            except Exception as e:
                continue
                
        self.scan_data['processes'] = analyzed_processes
                
    def assess_process_severity_advanced(self, name, path, command_line, pid):
        """Advanced process threat assessment"""
        threat_info = []
        
        # Check for processes from temp directories
        if path and ('temp' in path.lower() or '\\tmp\\' in path.lower() or '\\appdata\\local\\temp' in path.lower()):
            return SEVERITY_CRITICAL, f"Process running from temp directory: {name} - Highly suspicious, possible malware"
            
        # Check for suspicious process names with suspicious arguments
        if name.lower() in SUSPICIOUS_PROCESS_NAMES:
            if command_line:
                cmd_lower = command_line.lower()
                # Check for encoded commands (obfuscation)
                if '-encodedcommand' in cmd_lower or '-e ' in cmd_lower or '-enc ' in cmd_lower:
                    return SEVERITY_CRITICAL, f"Obfuscated {name} command with encoded payload - Clear sign of malware"
                # Check for download commands
                if 'downloadstring' in cmd_lower or 'invoke-webrequest' in cmd_lower or 'iwr' in cmd_lower:
                    return SEVERITY_CRITICAL, f"{name} with download capability - Possible dropper/loader"
                # Check for base64
                if 'frombase64string' in cmd_lower or '[convert]::frombase64' in cmd_lower:
                    return SEVERITY_CRITICAL, f"{name} with base64 decoding - Obfuscated payload execution"
                # Check for execution bypass
                if 'bypass' in cmd_lower or '-executionpolicy' in cmd_lower:
                    return SEVERITY_HIGH, f"{name} attempting execution policy bypass"
                    
        # Check for processes with no valid path
        if not path or path == 'N/A':
            return SEVERITY_HIGH, f"Process '{name}' has no executable path - Possible rootkit"
            
        # Check for processes from user profile with suspicious names
        if path and ('\\appdata\\' in path.lower() or '\\documents\\' in path.lower()):
            suspicious_files = ['update', 'install', 'setup', 'loader', 'dropper', 'payload', 'inject']
            if any(suspicious in path.lower() for suspicious in suspicious_files):
                return SEVERITY_HIGH, f"Suspicious executable in user directory: {path}"
                
        # Check for unsigned executables (would need file verification)
        # This is a placeholder - in production, check digital signatures
        
        # Check for parent process anomalies
        # Would need to build process tree to detect anomalies
        
        # Check for system processes with unexpected paths
        system_processes = ['svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe', 'services.exe']
        if name.lower() in system_processes:
            if path and not path.lower().startswith(('c:\\windows\\system32\\', 'c:\\windows\\syswow64\\')):
                return SEVERITY_CRITICAL, f"System process '{name}' running from non-standard location: {path}"
                
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal process"
        
    def scan_user_discovery(self):
        """Scan user accounts and privileges"""
        self.log_message("[User] Auditing user accounts...")
        
        try:
            # Get local users
            ps_command = "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon, Description | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                users = json.loads(result.stdout)
                
                user_file = os.path.join(LOG_DIR, "USER_AUDIT", "Local_Users.txt")
                with open(user_file, 'w') as f:
                    f.write("=== LOCAL USER ACCOUNTS ===\n")
                    f.write(json.dumps(users, indent=2))
                    
                self.parse_users(users)
                
            # Get admin group members
            result = subprocess.run(['net', 'localgroup', 'administrators'],
                                  capture_output=True, text=True, timeout=30)
            
            admin_file = os.path.join(LOG_DIR, "USER_AUDIT", "Admin_Group_Members.txt")
            with open(admin_file, 'w') as f:
                f.write("=== ADMINISTRATORS GROUP MEMBERS ===\n")
                f.write(result.stdout)
                
            self.log_message("[User] User audit completed")
            
        except subprocess.TimeoutExpired:
            self.log_message("[User] Command timed out")
        except Exception as e:
            self.log_message(f"[User] Error: {str(e)}")
            
    def parse_users(self, users):
        """Parse user accounts with advanced security analysis"""
        if not isinstance(users, list):
            users = [users]
            
        analyzed_users = []
        
        for user in users:
            try:
                name = user.get('Name', 'N/A')
                enabled = str(user.get('Enabled', 'N/A'))
                password_required = str(user.get('PasswordRequired', 'N/A'))
                last_logon = str(user.get('LastLogon', 'N/A'))
                description = user.get('Description', '')
                
                # Advanced severity assessment
                severity, threat_info = self.assess_user_severity_advanced(name, enabled, password_required, description)
                
                user_data = {
                    'name': name or 'N/A',
                    'enabled': enabled or 'N/A',
                    'password_required': password_required or 'N/A',
                    'last_logon': last_logon or 'N/A',
                    'description': description or '',
                    'severity': severity,
                    'threat_info': threat_info
                }
                analyzed_users.append(user_data)
                
                # Check if admin (simplified)
                is_admin = "Unknown"  # Would need additional query
                
                # Add to GUI with severity color tag
                severity_tag = severity.lower() if severity else 'info'
                self.root.after(0, lambda u=user_data, admin=is_admin, tag=severity_tag: self.user_tree.insert('', tk.END, values=(
                    u['name'],
                    u['enabled'],
                    u['password_required'],
                    u['last_logon'] if u['last_logon'] != 'N/A' else 'Never',
                    admin,
                    u['severity']
                ), tags=(tag,)))
                
                # Log high-severity findings
                if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                    self.log_message(f"[USER] {threat_info}")
                    self.add_threat(severity, "Suspicious User Account", threat_info, "user")
                    
            except Exception as e:
                continue
                
        self.scan_data['users'] = analyzed_users
                
    def assess_user_severity_advanced(self, name, enabled, password_required, description):
        """Advanced user account threat assessment"""
        threat_info = []
        
        # Check for enabled accounts without passwords
        if enabled.lower() == 'true' and password_required.lower() == 'false':
            return SEVERITY_CRITICAL, f"Account '{name}' has no password required - Critical security risk"
            
        # Check for suspicious usernames
        suspicious_names = ['admin', 'administrator', 'root', 'test', 'guest', 'support', 'user', 'temp']
        if any(suspicious in name.lower() for suspicious in suspicious_names):
            if name.lower() not in ['administrator', 'guest']:
                if enabled.lower() == 'true':
                    return SEVERITY_HIGH, f"Suspicious account name: '{name}' - Could be backdoor account"
                    
        # Check for recently created accounts (would need creation date)
        # This is a placeholder - in production, check account creation date
        
        # Check for accounts with suspicious descriptions
        if description:
            desc_lower = description.lower()
            suspicious_desc = ['temp', 'test', 'backup', 'service', 'maintenance', 'support']
            if any(suspicious in desc_lower for suspicious in suspicious_desc):
                return SEVERITY_MEDIUM, f"Account '{name}' has suspicious description: {description}"
                
        # Check for default accounts that shouldn't exist
        if name.lower() in ['support', 'help', 'user1', 'user2', 'test1', 'test2']:
            return SEVERITY_MEDIUM, f"Default-style account name: '{name}' - Verify legitimacy"
            
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal user account"
        
    def scan_persistence_hunting(self):
        """Scan persistence mechanisms"""
        self.log_message("[Persistence] Scanning persistence mechanisms...")
        
        try:
            # Get registry run keys
            run_keys = [
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            ]
            
            for key in run_keys:
                result = subprocess.run(['reg', 'query', key], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.parse_registry_key(key, result.stdout)
                    
            # Get scheduled tasks
            result = subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'],
                                  capture_output=True, text=True, timeout=120)
            
            tasks_file = os.path.join(LOG_DIR, "PERSISTENCE", "Scheduled_Tasks.txt")
            with open(tasks_file, 'w') as f:
                f.write("=== SCHEDULED TASKS ===\n")
                f.write(result.stdout)
                
            self.parse_scheduled_tasks(result.stdout)
            
            # Get services
            ps_command = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                services = json.loads(result.stdout)
                services_file = os.path.join(LOG_DIR, "PERSISTENCE", "Services_Audit.txt")
                with open(services_file, 'w') as f:
                    f.write("=== RUNNING SERVICES ===\n")
                    f.write(json.dumps(services, indent=2))
                    
                self.parse_services(services)
                
            self.log_message("[Persistence] Persistence scan completed")
            
        except subprocess.TimeoutExpired:
            self.log_message("[Persistence] Command timed out")
        except Exception as e:
            self.log_message(f"[Persistence] Error: {str(e)}")
            
    def parse_registry_key(self, key, data):
        """Parse registry key with advanced threat detection"""
        lines = data.split('\n')
        registry_entries = []
        
        for line in lines:
            line = line.strip()
            if 'REG_' in line and not line.startswith(key):
                try:
                    parts = re.split(r'\s{2,}', line)  # Split by multiple spaces
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        value_type = parts[1].strip() if len(parts) > 1 else 'REG_SZ'
                        value = parts[2].strip() if len(parts) > 2 else ''
                        
                        # Advanced severity assessment
                        severity, threat_info = self.assess_persistence_severity_advanced("Registry", name, value, key)
                        
                        entry = {
                            'type': 'Registry',
                            'name': name or 'N/A',
                            'location': key or 'N/A',
                            'value_type': value_type or 'REG_SZ',
                            'value': value or '',
                            'severity': severity,
                            'threat_info': threat_info
                        }
                        registry_entries.append(entry)
                        
                        # Format value for display
                        display_value = (value[:60] + '...' if value and len(value) > 60 else value or '')
                        
                        # Add to GUI with severity color tag
                        severity_tag = severity.lower() if severity else 'info'
                        self.root.after(0, lambda e=entry, dv=display_value, tag=severity_tag: self.persistence_tree.insert('', tk.END, values=(
                            e['type'],
                            e['name'],
                            (e['location'][-50:] if e['location'] and len(e['location']) > 50 else e['location'] or 'N/A'),
                            dv,
                            e['severity']
                        ), tags=(tag,)))
                        
                        # Log high-severity findings
                        if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                            self.log_message(f"[REGISTRY] {threat_info}")
                            self.add_threat(severity, "Suspicious Registry Entry", threat_info, "persistence")
                            
                except Exception:
                    continue
                    
        self.scan_data[f'registry_{key.replace("\\", "_")}'] = registry_entries
                    
    def parse_scheduled_tasks(self, data):
        """Parse scheduled tasks"""
        # Simplified parser
        lines = data.split('\n')
        task_name = None
        for line in lines:
            if 'TaskName:' in line:
                task_name = line.split(':', 1)[1].strip()
            elif task_name and ('To Run:' in line or 'Command:' in line):
                command = line.split(':', 1)[1].strip()
                severity = self.assess_persistence_severity("Scheduled Task", task_name, command)
                
                # Add to GUI with severity color tag
                severity_tag = severity.lower() if severity else 'info'
                self.root.after(0, lambda tn=task_name, cmd=command, s=severity, tag=severity_tag: self.persistence_tree.insert('', tk.END, values=(
                    "Scheduled Task", tn, "Task Scheduler", cmd, s
                ), tags=(tag,)))
                task_name = None
                
    def parse_services(self, services):
        """Parse services and populate treeview"""
        if not isinstance(services, list):
            services = [services]
            
        for svc in services:
            try:
                name = svc.get('Name', 'N/A')
                display_name = svc.get('DisplayName', 'N/A')
                status = svc.get('Status', 'N/A')
                
                severity = self.assess_persistence_severity("Service", name, display_name)
                
                # Add to GUI with severity color tag
                severity_tag = severity.lower() if severity else 'info'
                self.root.after(0, lambda s=svc, sev=severity, tag=severity_tag: self.persistence_tree.insert('', tk.END, values=(
                    "Service",
                    s.get('Name', 'N/A'),
                    "Services",
                    s.get('DisplayName', 'N/A'),
                    sev
                ), tags=(tag,)))
                
            except Exception:
                continue
                
    def assess_persistence_severity_advanced(self, ptype, name, value, location):
        """Advanced persistence mechanism threat assessment"""
        threat_info = []
        
        # Check for temp directory references
        if value and ('temp' in value.lower() or '\\tmp\\' in value.lower() or '\\appdata\\local\\temp' in value.lower()):
            return SEVERITY_CRITICAL, f"{ptype} pointing to temp directory: {name} - Classic malware persistence"
            
        # Check for suspicious names
        suspicious_names = ['update', 'install', 'download', 'loader', 'dropper', 'payload', 'inject', 'hook', 'backdoor', 'shell', 'c2', 'bot']
        if any(suspicious in name.lower() for suspicious in suspicious_names):
            return SEVERITY_HIGH, f"Suspicious {ptype} name: {name} - Possible malware persistence"
            
        # Check for obfuscated commands
        if value and ('-encoded' in value.lower() or 'base64' in value.lower() or 'frombase64' in value.lower()):
            return SEVERITY_CRITICAL, f"{ptype} with obfuscated command: {name} - Clear sign of malware"
            
        # Check for web downloads in persistence
        if value and ('downloadstring' in value.lower() or 'invoke-webrequest' in value.lower() or 'iwr' in value.lower()):
            return SEVERITY_CRITICAL, f"{ptype} with download capability: {name} - Possible dropper"
            
        # Check for non-Microsoft services in critical locations
        if ptype == "Service" and 'microsoft' not in name.lower() and 'windows' not in name.lower():
            # Check if it's a third-party service
            if value and ('system32' not in value.lower() and 'syswow64' not in value.lower()):
                return SEVERITY_MEDIUM, f"Non-Microsoft service: {name} - Verify legitimacy"
                
        # Check for registry keys in unusual locations
        if ptype == "Registry" and location:
            if 'runonce' in location.lower():
                return SEVERITY_HIGH, f"RunOnce registry entry: {name} - Executes once, often used by malware"
                
        # Check for scheduled tasks with suspicious triggers
        if ptype == "Scheduled Task" and value:
            if 'at logon' in value.lower() or 'at startup' in value.lower():
                if 'microsoft' not in name.lower():
                    return SEVERITY_MEDIUM, f"Auto-start scheduled task: {name} - Verify legitimacy"
                    
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal persistence mechanism"
        
    def scan_filesystem_forensics(self):
        """Scan file system with advanced malware detection"""
        self.log_message("[Files] Performing deep file system analysis...")
        
        try:
            suspicious_files = []
            
            # Scan critical directories for recently modified files
            critical_paths = [
                os.path.expandvars('%SystemRoot%\\System32'),
                os.path.expandvars('%SystemRoot%\\System32\\drivers'),
                os.path.expandvars('%ProgramData%'),
                os.path.expandvars('%TEMP%'),
                os.path.expandvars('%AppData%\\Local\\Temp'),
                os.path.expandvars('%AppData%\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                os.path.expandvars('%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp')
            ]
            
            for path in critical_paths:
                if os.path.exists(path):
                    self.log_message(f"[Files] Scanning {path}...")
                    found = self.scan_directory_advanced(path)
                    suspicious_files.extend(found)
                    
            # Scan user profile directories for suspicious executables
            user_profile = os.path.expanduser('~')
            user_dirs = [
                os.path.join(user_profile, 'Downloads'),
                os.path.join(user_profile, 'Desktop'),
                os.path.join(user_profile, 'Documents'),
                os.path.join(user_profile, 'AppData\\Roaming'),
                os.path.join(user_profile, 'AppData\\Local')
            ]
            
            for user_dir in user_dirs:
                if os.path.exists(user_dir):
                    self.log_message(f"[Files] Scanning {user_dir}...")
                    found = self.scan_directory_advanced(user_dir, max_depth=2)
                    suspicious_files.extend(found)
                    
            self.scan_data['suspicious_files'] = suspicious_files
            self.log_message(f"[Files] Found {len(suspicious_files)} suspicious files")
            
        except Exception as e:
            self.log_message(f"[Files] Error: {str(e)}")
            
    def scan_directory_advanced(self, path, max_depth=5):
        """Advanced directory scan with malware detection"""
        suspicious_files = []
        cutoff_time = time.time() - (7 * 24 * 60 * 60)  # 7 days
        
        try:
            for root, dirs, files in os.walk(path):
                # Check depth
                depth = root[len(path):].count(os.sep)
                if depth > max_depth:
                    dirs[:] = []  # Don't recurse deeper
                    continue
                    
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        
                        # Check file extension
                        ext = os.path.splitext(file)[1].lower()
                        suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.js', '.jar', '.com', '.pif']
                        
                        if ext in suspicious_extensions:
                            # Get file info
                            mod_time = os.path.getmtime(file_path)
                            size = os.path.getsize(file_path)
                            mod_time_str = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                            
                            # Advanced severity assessment
                            severity, threat_info = self.assess_file_severity_advanced(file_path, ext, mod_time, size)
                            
                            # Calculate hash for suspicious files
                            file_hash = self.calculate_hash(file_path) if severity != SEVERITY_INFO else "N/A"
                            
                            file_data = {
                                'name': file or 'N/A',
                                'path': file_path or 'N/A',
                                'size': size or 0,
                                'modified': mod_time_str or 'N/A',
                                'hash': file_hash or 'N/A',
                                'severity': severity,
                                'threat_info': threat_info
                            }
                            suspicious_files.append(file_data)
                            
                            # Add to GUI with severity color tag
                            severity_tag = severity.lower() if severity else 'info'
                            self.root.after(0, lambda fd=file_data, tag=severity_tag: self.filesystem_tree.insert('', tk.END, values=(
                                fd['name'],
                                (fd['path'][:70] + '...' if fd['path'] and len(fd['path']) > 70 else fd['path'] or 'N/A'),
                                self.format_size(fd['size']),
                                fd['modified'],
                                (fd['hash'][:16] + '...' if fd['hash'] and fd['hash'] != 'N/A' and len(fd['hash']) > 16 else fd['hash'] or 'N/A'),
                                fd['severity']
                            ), tags=(tag,)))
                            
                            # Log high-severity findings
                            if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                                self.log_message(f"[FILES] {threat_info}")
                                self.add_threat(severity, "Suspicious File", threat_info, "filesystem")
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            self.log_message(f"[Files] Error scanning {path}: {str(e)}")
            
        return suspicious_files
            
    def calculate_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "Error calculating hash"
            
    def format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
        
    def assess_file_severity_advanced(self, file_path, ext, mod_time, size):
        """Advanced file threat assessment"""
        threat_info = []
        
        # Check for files in temp directories
        if 'temp' in file_path.lower():
            return SEVERITY_CRITICAL, f"Executable in temp directory: {file_path} - Classic malware behavior"
            
        # Check for recently modified system files
        if 'system32' in file_path.lower() or 'syswow64' in file_path.lower():
            if mod_time > time.time() - (1 * 24 * 60 * 60):  # Last 24 hours
                return SEVERITY_CRITICAL, f"Recently modified system file: {file_path} - Possible system compromise"
                
        # Check for suspicious file names
        suspicious_names = ['update', 'install', 'setup', 'loader', 'dropper', 'payload', 'inject', 'hook', 'backdoor', 'shell', 'c2', 'bot', 'crack', 'patch', 'keygen']
        file_name = os.path.basename(file_path).lower()
        if any(suspicious in file_name for suspicious in suspicious_names):
            return SEVERITY_HIGH, f"Suspicious filename: {file_name} - Possible malware"
            
        # Check for scripts in user directories
        if ext in ['.ps1', '.vbs', '.js', '.bat']:
            if 'appdata' in file_path.lower() or 'documents' in file_path.lower() or 'downloads' in file_path.lower():
                return SEVERITY_HIGH, f"Script in user directory: {file_path} - Possible malware persistence"
                
        # Check for very small executables (could be droppers)
        if ext in ['.exe', '.dll'] and size < 10240:  # Less than 10KB
            return SEVERITY_MEDIUM, f"Very small executable: {file_path} ({size} bytes) - Possible dropper"
            
        # Check for very large executables in unusual locations
        if ext in ['.exe', '.dll'] and size > 104857600:  # Greater than 100MB
            if 'temp' in file_path.lower() or 'downloads' in file_path.lower():
                return SEVERITY_MEDIUM, f"Large executable in unusual location: {file_path} - Investigate"
                
        # Check for double extensions (e.g., file.exe.pdf)
        if file_name.count('.') > 1:
            return SEVERITY_HIGH, f"File with multiple extensions: {file_name} - Possible obfuscation"
            
        # Check for files with random-looking names (high entropy)
        if self.is_random_filename(file_name):
            if ext in ['.exe', '.dll']:
                return SEVERITY_MEDIUM, f"Random-looking filename: {file_name} - Possible malware"
                
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal file"
        
    def is_random_filename(self, filename):
        """Check if filename appears random (high entropy)"""
        # Remove extension
        name = os.path.splitext(filename)[0]
        
        # Check for high ratio of alphanumeric characters
        if len(name) < 8:
            return False
            
        # Check for random-looking patterns (many consonants, few vowels)
        vowels = sum(1 for c in name.lower() if c in 'aeiou')
        consonants = sum(1 for c in name.lower() if c.isalpha() and c not in 'aeiou')
        
        if consonants > 0 and vowels / consonants < 0.3:
            return True
            
        # Check for hex-like patterns
        if re.match(r'^[a-f0-9]{8,}$', name):
            return True
            
        return False
        
    def scan_firewall_hosts(self):
        """Scan firewall rules and hosts file"""
        self.log_message("[Firewall] Auditing firewall and hosts...")
        
        try:
            # Get firewall rules
            result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                                  capture_output=True, text=True, timeout=120)
            
            firewall_file = os.path.join(LOG_DIR, "FIREWALL_HOSTS", "Firewall_Rules.txt")
            with open(firewall_file, 'w') as f:
                f.write("=== FIREWALL RULES ===\n")
                f.write(result.stdout)
                
            self.parse_firewall_rules(result.stdout)
            
            # Get hosts file
            hosts_path = os.path.join(os.environ['WINDIR'], 'System32', 'drivers', 'etc', 'hosts')
            if os.path.exists(hosts_path):
                with open(hosts_path, 'r') as f:
                    hosts_content = f.read()
                    
                hosts_file = os.path.join(LOG_DIR, "FIREWALL_HOSTS", "Hosts_File.txt")
                with open(hosts_file, 'w') as f:
                    f.write("=== HOSTS FILE ===\n")
                    f.write(hosts_content)
                    
                self.parse_hosts_file(hosts_content)
                
            self.log_message("[Firewall] Firewall audit completed")
            
        except subprocess.TimeoutExpired:
            self.log_message("[Firewall] Command timed out")
        except Exception as e:
            self.log_message(f"[Firewall] Error: {str(e)}")
            
    def parse_firewall_rules(self, data):
        """Parse firewall rules with advanced security analysis"""
        lines = data.split('\n')
        firewall_rules = []
        rule_name = None
        direction = action = protocol = ports = profile = "N/A"
        
        for line in lines:
            line = line.strip()
            
            if 'Rule Name:' in line:
                # Save previous rule
                if rule_name:
                    severity, threat_info = self.assess_firewall_severity_advanced(rule_name, direction, action, protocol, ports, profile)
                    
                    rule = {
                        'name': rule_name or 'N/A',
                        'direction': direction or 'N/A',
                        'action': action or 'N/A',
                        'protocol': protocol or 'N/A',
                        'ports': ports or 'N/A',
                        'profile': profile or 'N/A',
                        'severity': severity,
                        'threat_info': threat_info
                    }
                    firewall_rules.append(rule)
                    
                    # Add to GUI with severity color tag
                    severity_tag = severity.lower() if severity else 'info'
                    self.root.after(0, lambda r=rule, tag=severity_tag: self.firewall_tree.insert('', tk.END, values=(
                        "Firewall Rule",
                        (r['name'][:50] + '...' if r['name'] and len(r['name']) > 50 else r['name'] or 'N/A'),
                        r['direction'],
                        r['action'],
                        r['protocol'],
                        r['ports'],
                        r['severity']
                    ), tags=(tag,)))
                    
                    if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                        self.log_message(f"[FIREWALL] {threat_info}")
                        self.add_threat(severity, "Suspicious Firewall Rule", threat_info, "firewall")
                        
                rule_name = line.split(':', 1)[1].strip()
                direction = action = protocol = ports = profile = "N/A"
                
            elif 'Direction:' in line:
                direction = line.split(':', 1)[1].strip()
            elif 'Action:' in line:
                action = line.split(':', 1)[1].strip()
            elif 'Protocol:' in line:
                protocol = line.split(':', 1)[1].strip()
            elif 'Local Port:' in line or 'Remote Port:' in line:
                ports = line.split(':', 1)[1].strip()
            elif 'Profile:' in line:
                profile = line.split(':', 1)[1].strip()
                
        # Save last rule
        if rule_name:
            severity, threat_info = self.assess_firewall_severity_advanced(rule_name, direction, action, protocol, ports, profile)
            
            rule = {
                'name': rule_name,
                'direction': direction,
                'action': action,
                'protocol': protocol,
                'ports': ports,
                'profile': profile,
                'severity': severity,
                'threat_info': threat_info
            }
            firewall_rules.append(rule)
            
            # Add to GUI with severity color tag
            severity_tag = severity.lower() if severity else 'info'
            self.root.after(0, lambda r=rule, tag=severity_tag: self.firewall_tree.insert('', tk.END, values=(
                "Firewall Rule",
                r['name'][:50] + '...' if len(r['name']) > 50 else r['name'],
                r['direction'],
                r['action'],
                r['protocol'],
                r['ports'],
                r['severity']
            ), tags=(tag,)))
            
        self.scan_data['firewall_rules'] = firewall_rules
                
    def parse_hosts_file(self, content):
        """Parse hosts file for suspicious entries"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hostname = parts[1]
                    
                    # Check for non-standard entries
                    if not hostname.startswith('#') and hostname not in ['localhost', 'localhost.localdomain']:
                        severity = SEVERITY_MEDIUM
                        severity_tag = severity.lower() if severity else 'info'
                        self.root.after(0, lambda ip=ip, hn=hostname, s=severity, tag=severity_tag: 
                            self.firewall_tree.insert('', tk.END, values=("Hosts Entry", hn, "N/A", "N/A", "N/A", ip, s), tags=(tag,)))
                        
    def assess_firewall_severity_advanced(self, rule_name, direction, action, protocol, ports, profile):
        """Advanced firewall rule threat assessment"""
        threat_info = []
        
        # Check for allow-all rules
        if action == "Allow" and ports in ["Any", "0-65535", "*"]:
            return SEVERITY_CRITICAL, f"Allow-all firewall rule: {rule_name} - Completely open, major security risk"
            
        # Check for allow rules on suspicious ports
        if action == "Allow" and ports:
            for suspicious_port in SUSPICIOUS_PORTS:
                if suspicious_port in ports:
                    return SEVERITY_HIGH, f"Allow rule on suspicious port {suspicious_port}: {rule_name}"
                    
        # Check for inbound allow rules
        if direction == "In" and action == "Allow":
            if protocol == "Any" or ports == "Any":
                return SEVERITY_HIGH, f"Inbound allow-all rule: {rule_name} - Allows all inbound traffic"
                
        # Check for rules allowing RDP from anywhere
        if action == "Allow" and "3389" in ports:
            if "Any" in ports or "0.0.0.0" in ports:
                return SEVERITY_HIGH, f"RDP exposed to internet: {rule_name} - Brute force risk"
                
        # Check for disabled firewall (no blocking rules)
        # This would require analyzing the overall rule set
        
        # Check for rules with suspicious names
        suspicious_names = ['temp', 'test', 'backup', 'p2p', 'torrent', 'game', 'crack']
        if any(suspicious in rule_name.lower() for suspicious in suspicious_names):
            return SEVERITY_MEDIUM, f"Suspicious firewall rule name: {rule_name}"
            
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal firewall rule"
        
    def scan_event_logs(self):
        """Scan security event logs"""
        self.log_message("[Events] Analyzing event logs...")
        
        try:
            # Get failed logins (Event 4625)
            ps_command = "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout:
                try:
                    failed_logins = json.loads(result.stdout)
                    failed_file = os.path.join(LOG_DIR, "EVENT_LOGS", "Failed_Logins.txt")
                    with open(failed_file, 'w') as f:
                        f.write("=== FAILED LOGIN ATTEMPTS ===\n")
                        f.write(json.dumps(failed_logins, indent=2))
                        
                    self.parse_security_events(failed_logins, "Failed Login", 4625)
                except json.JSONDecodeError:
                    pass
                    
            # Get successful logins (Event 4624)
            ps_command = "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout:
                try:
                    successful_logins = json.loads(result.stdout)
                    success_file = os.path.join(LOG_DIR, "EVENT_LOGS", "Successful_Logins.txt")
                    with open(success_file, 'w') as f:
                        f.write("=== SUCCESSFUL LOGINS ===\n")
                        f.write(json.dumps(successful_logins, indent=2))
                        
                    self.parse_security_events(successful_logins, "Successful Login", 4624)
                except json.JSONDecodeError:
                    pass
                    
            self.log_message("[Events] Event log analysis completed")
            
        except subprocess.TimeoutExpired:
            self.log_message("[Events] Command timed out")
        except Exception as e:
            self.log_message(f"[Events] Error: {str(e)}")
            
    def parse_security_events(self, events, event_type, event_id):
        """Parse security events with advanced threat detection"""
        if not isinstance(events, list):
            events = [events]
            
        analyzed_events = []
        
        for event in events:
            try:
                time = str(event.get('TimeCreated', 'N/A'))
                message = str(event.get('Message', 'N/A'))
                
                # Advanced severity assessment
                severity, threat_info = self.assess_event_severity_advanced(event_type, event_id, message)
                
                event_data = {
                    'time': time or 'N/A',
                    'event_id': event_id or 'N/A',
                    'source': 'Security',
                    'message': message or 'N/A',
                    'severity': severity,
                    'threat_info': threat_info
                }
                analyzed_events.append(event_data)
                
                # Format message for display
                display_message = (message[:80] + '...' if message and len(message) > 80 else message or 'N/A')
                
                # Add to GUI with severity color tag
                severity_tag = severity.lower() if severity else 'info'
                self.root.after(0, lambda e=event_data, dm=display_message, tag=severity_tag: 
                    self.eventlogs_tree.insert('', tk.END, values=(e['time'], e['event_id'], e['source'], dm, e['severity']), tags=(tag,)))
                
                # Log high-severity findings
                if severity in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
                    self.log_message(f"[EVENTS] {threat_info}")
                    self.add_threat(severity, f"Security Event: {event_type}", threat_info, "eventlogs")
                    
            except Exception:
                continue
                
        self.scan_data[f'events_{event_type}'] = analyzed_events
                
    def assess_event_severity_advanced(self, event_type, event_id, message):
        """Advanced security event threat assessment"""
        threat_info = []
        message_lower = message.lower()
        
        # Failed login analysis
        if event_type == "Failed Login" or event_id == 4625:
            # Check for multiple failed logins from same source
            if "failure reason" in message_lower:
                # Check for specific failure reasons
                if "bad password" in message_lower:
                    return SEVERITY_HIGH, "Failed login with bad password - Possible brute force attack"
                elif "account locked out" in message_lower:
                    return SEVERITY_HIGH, "Account lockout event - Possible brute force attack"
                    
            # Check for unknown username
            if "unknown user name" in message_lower:
                return SEVERITY_MEDIUM, "Failed login with unknown username - Account enumeration"
                
            return SEVERITY_HIGH, "Failed login attempt - Investigate for brute force"
            
        # Successful login analysis
        if event_type == "Successful Login" or event_id == 4624:
            # Check for logons at unusual times (would need time analysis)
            # Check for logons from unusual locations
            if "network" in message_lower and "ip address" in message_lower:
                # Extract IP and check if foreign
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                if ip_match:
                    ip = ip_match.group(1)
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_private and not ip_obj.is_loopback:
                            return SEVERITY_HIGH, f"Successful login from foreign IP: {ip} - Investigate"
                    except ValueError:
                        pass
                        
            # Check for special privileges
            if "elevated token" in message_lower or "administrator" in message_lower:
                return SEVERITY_MEDIUM, "Privileged login event - Verify legitimacy"
                
        # PowerShell script block logging
        if event_id == 4104:
            # Check for obfuscated scripts
            if "-encodedcommand" in message_lower or "frombase64" in message_lower:
                return SEVERITY_CRITICAL, "Obfuscated PowerShell execution - Clear malware indicator"
            # Check for download commands
            if "downloadstring" in message_lower or "invoke-webrequest" in message_lower:
                return SEVERITY_CRITICAL, "PowerShell download command - Possible malware dropper"
            # Check for execution policy bypass
            if "executionpolicy" in message_lower or "bypass" in message_lower:
                return SEVERITY_HIGH, "PowerShell execution policy bypass - Suspicious activity"
                
        # Process creation events
        if event_id == 4688:
            # Check for suspicious command lines
            if "powershell" in message_lower and ("-encoded" in message_lower or "-e " in message_lower):
                return SEVERITY_CRITICAL, "Encoded PowerShell command - Malware indicator"
            if "cmd.exe" in message_lower and "/c" in message_lower:
                return SEVERITY_MEDIUM, "CMD with /c flag - Investigate command"
                
        if threat_info:
            return SEVERITY_MEDIUM, "; ".join(threat_info)
            
        return SEVERITY_INFO, "Normal security event"
        
    def scan_system_integrity(self):
        """Perform system integrity check"""
        self.log_message("[System] Checking system integrity...")
        
        try:
            # Flush DNS cache
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, timeout=30)
            
            # Clear temp files
            temp_dir = os.path.expandvars('%TEMP%')
            if os.path.exists(temp_dir):
                severity_tag = 'info'
                self.root.after(0, lambda: self.system_tree.insert('', tk.END, values=(
                    "Cache", "Temp Directory", temp_dir, "Cleared", SEVERITY_INFO
                ), tags=(severity_tag,)))
                
            # System info
            ps_command = "Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsVersion, CsName | ConvertTo-Json"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                sys_info = json.loads(result.stdout)
                sys_file = os.path.join(LOG_DIR, "METADATA", "System_Info.txt")
                with open(sys_file, 'w') as f:
                    f.write("=== SYSTEM INFORMATION ===\n")
                    f.write(json.dumps(sys_info, indent=2))
                    
                self.parse_system_info(sys_info)
                
            # Save scan metadata
            metadata_file = os.path.join(LOG_DIR, "METADATA", "Scan_Timestamp.txt")
            with open(metadata_file, 'w') as f:
                f.write(f"Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tool Version: {APP_VERSION}\n")
                
            self.log_message("[System] System integrity check completed")
            
        except subprocess.TimeoutExpired:
            self.log_message("[System] Command timed out")
        except Exception as e:
            self.log_message(f"[System] Error: {str(e)}")
            
    def parse_system_info(self, sys_info):
        """Parse system info and populate treeview"""
        items = [
            ("OS Name", sys_info.get('OsName', 'N/A')),
            ("OS Version", sys_info.get('OsVersion', 'N/A')),
            ("Windows Version", sys_info.get('WindowsVersion', 'N/A')),
            ("Computer Name", sys_info.get('CsName', 'N/A'))
        ]
        
        for item_name, item_value in items:
            severity_tag = 'info'
            self.root.after(0, lambda iname=item_name, ivalue=item_value, tag=severity_tag: 
                self.system_tree.insert('', tk.END, values=("System Info", iname, ivalue, "OK", SEVERITY_INFO), tags=(tag,)))
                
    def add_threat(self, severity, title, description, category):
        """Add threat to threat database and trigger critical alert if needed"""
        threat = {
            'severity': severity,
            'title': title,
            'description': description,
            'category': category,
            'timestamp': datetime.now().isoformat()
        }
        self.threats[severity].append(threat)
        
        # Update threat monitoring panel with category
        self.update_threat_monitor(severity, title, description, category)
        
        # Show critical alert if critical threat detected
        if severity == SEVERITY_CRITICAL:
            self.show_critical_alert()
        
        # Send Telegram alert
        if self.telegram_bot and self.telegram_bot.running:
            self.telegram_bot.send_alert(severity, title, description, category)
        
    def update_threat_summary(self):
        """Update threat summary labels"""
        self.root.after(0, lambda: self.critical_label.config(text=f"Critical: {len(self.threats[SEVERITY_CRITICAL])}"))
        self.root.after(0, lambda: self.high_label.config(text=f"High: {len(self.threats[SEVERITY_HIGH])}"))
        self.root.after(0, lambda: self.medium_label.config(text=f"Medium: {len(self.threats[SEVERITY_MEDIUM])}"))
        self.root.after(0, lambda: self.low_label.config(text=f"Low: {len(self.threats[SEVERITY_LOW])}"))
        
    def generate_summary_report(self):
        """Generate summary report with recommendations"""
        try:
            summary_file = os.path.join(LOG_DIR, "SUMMARY", "Executive_Summary.txt")
            
            with open(summary_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("CYBER FORENSICS EXECUTIVE SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tool Version: {APP_VERSION}\n\n")
                
                f.write("THREAT SUMMARY\n")
                f.write("-" * 80 + "\n")
                f.write(f"Critical: {len(self.threats[SEVERITY_CRITICAL])}\n")
                f.write(f"High: {len(self.threats[SEVERITY_HIGH])}\n")
                f.write(f"Medium: {len(self.threats[SEVERITY_MEDIUM])}\n")
                f.write(f"Low: {len(self.threats[SEVERITY_LOW])}\n\n")
                
                f.write("CRITICAL THREATS\n")
                f.write("-" * 80 + "\n")
                for threat in self.threats[SEVERITY_CRITICAL]:
                    f.write(f"- {threat['title']}\n")
                    f.write(f"  {threat['description']}\n")
                    f.write(f"  Category: {threat['category']}\n")
                    f.write(f"  Time: {threat['timestamp']}\n\n")
                    
                f.write("HIGH SEVERITY THREATS\n")
                f.write("-" * 80 + "\n")
                for threat in self.threats[SEVERITY_HIGH]:
                    f.write(f"- {threat['title']}\n")
                    f.write(f"  {threat['description']}\n")
                    f.write(f"  Category: {threat['category']}\n\n")
                    
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 80 + "\n")
                self.write_recommendations(f)
                
                f.write("\nEXTERNAL REFERENCES\n")
                f.write("-" * 80 + "\n")
                for name, url in URLS.items():
                    f.write(f"- {name.replace('_', ' ').title()}: {url}\n")
                    
            self.log_message("Summary report generated")
            
        except Exception as e:
            self.log_message(f"Error generating summary: {str(e)}")
            
    def write_recommendations(self, f):
        """Write recommendations to report"""
        # Critical threats
        if self.threats[SEVERITY_CRITICAL]:
            f.write("\nCRITICAL RECOMMENDATIONS (Immediate Action Required)\n")
            f.write("1. Isolate affected system from network\n")
            f.write("2. Review critical threats listed above\n")
            f.write("3. Upload suspicious files to VirusTotal: https://www.virustotal.com/\n")
            f.write("4. Check IP addresses at AbuseIPDB: https://www.abuseipdb.com/\n")
            f.write("5. Review MITRE ATT&CK for related techniques: https://attack.mitre.org/\n")
            
        # High threats
        if self.threats[SEVERITY_HIGH]:
            f.write("\nHIGH PRIORITY RECOMMENDATIONS\n")
            f.write("1. Investigate high severity threats\n")
            f.write("2. Review user accounts for unauthorized access\n")
            f.write("3. Audit firewall rules for unnecessary allow rules\n")
            f.write("4. Review scheduled tasks for suspicious entries\n")
            
        # Medium threats
        if self.threats[SEVERITY_MEDIUM]:
            f.write("\nMEDIUM PRIORITY RECOMMENDATIONS\n")
            f.write("1. Review medium severity findings\n")
            f.write("2. Implement security best practices\n")
            f.write("3. Review system configuration\n")
            
        f.write("\nGENERAL SECURITY RECOMMENDATIONS\n")
        f.write("1. Keep Windows and all software updated\n")
        f.write("2. Use strong, unique passwords\n")
        f.write("3. Enable Windows Defender or other antivirus\n")
        f.write("4. Enable Windows Firewall\n")
        f.write("5. Regular security audits\n")
        f.write("6. User security awareness training\n")
        f.write("7. Backup important data regularly\n")
        f.write("8. Monitor security event logs\n")
        
    def show_item_details(self, category):
        """Show detailed forensics analysis for selected item"""
        tree = getattr(self, f"{category}_tree", None)
        if not tree:
            return
            
        selection = tree.selection()
        if not selection:
            return
            
        item = tree.item(selection[0])
        values = item['values']
        
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        
        # Professional header
        self.detail_text.insert(tk.END, "=" * 60 + "\n")
        self.detail_text.insert(tk.END, f"FORENSIC ANALYSIS: {category.upper()}\n")
        self.detail_text.insert(tk.END, "=" * 60 + "\n\n")
        
        # Display item details with labels
        column_labels = {
            'network': ['Process', 'Local Address', 'Remote Address', 'State', 'Severity'],
            'process': ['Process Name', 'PID', 'CPU %', 'Memory (MB)', 'Path', 'Severity'],
            'user': ['Username', 'Enabled', 'Password Req', 'Last Logon', 'Admin', 'Severity'],
            'persistence': ['Type', 'Name', 'Location', 'Value/Command', 'Severity'],
            'filesystem': ['File Name', 'Path', 'Size', 'Modified', 'SHA256', 'Severity'],
            'firewall': ['Type', 'Rule Name', 'Direction', 'Action', 'Protocol', 'Ports', 'Severity'],
            'eventlogs': ['Time', 'Event ID', 'Source', 'Message', 'Severity'],
            'system': ['Category', 'Item', 'Value', 'Status', 'Severity']
        }
        
        labels = column_labels.get(category, ['Field'] * len(values))
        
        for i, (label, value) in enumerate(zip(labels, values)):
            self.detail_text.insert(tk.END, f"{label}:\n")
            self.detail_text.insert(tk.END, f"  {value}\n\n")
            
        # Add MITRE ATT&CK mapping
        self.detail_text.insert(tk.END, "\n" + "=" * 60 + "\n")
        self.detail_text.insert(tk.END, "MITRE ATT&CK TECHNIQUE MAPPING\n")
        self.detail_text.insert(tk.END, "=" * 60 + "\n\n")
        
        attack_mapping = self.get_mitre_mapping(category, values)
        if attack_mapping:
            for technique_id, technique_name, url in attack_mapping:
                self.detail_text.insert(tk.END, f"• {technique_id}: {technique_name}\n")
                self.detail_text.insert(tk.END, f"  {url}\n\n")
        else:
            self.detail_text.insert(tk.END, "No specific MITRE ATT&CK technique mapped\n\n")
            
        # Add detailed recommendations
        self.detail_text.insert(tk.END, "\n" + "=" * 60 + "\n")
        self.detail_text.insert(tk.END, "IMMEDIATE ACTIONS\n")
        self.detail_text.insert(tk.END, "=" * 60 + "\n\n")
        
        recommendations = self.get_detailed_recommendations(category, values)
        for i, rec in enumerate(recommendations, 1):
            self.detail_text.insert(tk.END, f"{i}. {rec}\n")
            
        # Add external resources
        self.detail_text.insert(tk.END, "\n" + "=" * 60 + "\n")
        self.detail_text.insert(tk.END, "EXTERNAL INTELLIGENCE RESOURCES\n")
        self.detail_text.insert(tk.END, "=" * 60 + "\n\n")
        
        resources = self.get_external_resources(category, values)
        for name, url in resources:
            self.detail_text.insert(tk.END, f"• {name}:\n")
            self.detail_text.insert(tk.END, f"  {url}\n\n")
            
        self.detail_text.config(state=tk.DISABLED)
        
    def get_mitre_mapping(self, category, values):
        """Get MITRE ATT&CK technique mapping for the finding"""
        mappings = []
        
        if category == "network":
            if "Foreign" in str(values) or "suspicious" in str(values).lower():
                mappings.append(("T1071", "Application Layer Protocol", "https://attack.mitre.org/techniques/T1071/"))
                mappings.append(("T1571", "DNS Tunneling", "https://attack.mitre.org/techniques/T1571/"))
        elif category == "process":
            if "temp" in str(values).lower():
                mappings.append(("T1055", "Process Injection", "https://attack.mitre.org/techniques/T1055/"))
                mappings.append(("T1059", "Command and Scripting Interpreter", "https://attack.mitre.org/techniques/T1059/"))
        elif category == "persistence":
            mappings.append(("T1053", "Scheduled Task/Job", "https://attack.mitre.org/techniques/T1053/"))
            mappings.append(("T1063", "Startup Items", "https://attack.mitre.org/techniques/T1063/"))
        elif category == "filesystem":
            mappings.append(("T1005", "Data from Local System", "https://attack.mitre.org/techniques/T1005/"))
        elif category == "eventlogs":
            if "Failed" in str(values) or "4625" in str(values):
                mappings.append(("T1110", "Brute Force", "https://attack.mitre.org/techniques/T1110/"))
                mappings.append(("T1078", "Valid Accounts", "https://attack.mitre.org/techniques/T1078/"))
                
        return mappings
        
    def get_detailed_recommendations(self, category, values):
        """Get detailed, actionable recommendations"""
        recommendations = []
        
        if category == "network":
            recommendations.append("Isolate the system from the network if suspicious connections are detected")
            recommendations.append("Capture network traffic using Wireshark for deeper analysis")
            recommendations.append("Check IP reputation at AbuseIPDB: https://www.abuseipdb.com/")
            recommendations.append("Block malicious IPs in Windows Firewall")
            recommendations.append("Investigate the process responsible for the connection")
            recommendations.append("Review DNS cache for additional suspicious domains")
            
        elif category == "process":
            recommendations.append("Upload the executable to VirusTotal for malware analysis")
            recommendations.append("Check file hash at VirusTotal and Hybrid Analysis")
            recommendations.append("Verify digital signature of the executable")
            recommendations.append("Analyze the process parent-child relationship chain")
            recommendations.append("Check for memory injection using Process Hacker")
            recommendations.append("Quarantine the file if confirmed malicious")
            
        elif category == "user":
            recommendations.append("Review account creation and modification dates")
            recommendations.append("Check for suspicious group memberships")
            recommendations.append("Audit recent login attempts and locations")
            recommendations.append("Disable unused or suspicious accounts")
            recommendations.append("Enforce strong password policies")
            recommendations.append("Enable account lockout policies")
            
        elif category == "persistence":
            recommendations.append("Verify the legitimacy of the startup item")
            recommendations.append("Check the digital signature of the executable")
            recommendations.append("Review the scheduled task trigger and action")
            recommendations.append("Audit service dependencies and configuration")
            recommendations.append("Monitor for registry key modifications")
            recommendations.append("Use Autoruns.exe for comprehensive persistence analysis")
            
        elif category == "filesystem":
            recommendations.append("Scan the file with Windows Defender and secondary antivirus")
            recommendations.append("Calculate and check file hash against threat intelligence feeds")
            recommendations.append("Analyze file behavior in a sandbox (Cuckoo, Joe Sandbox)")
            recommendations.append("Check file metadata (creation time, author, version info)")
            recommendations.append("Quarantine suspicious files immediately")
            recommendations.append("Monitor for file modifications using file integrity monitoring")
            
        elif category == "firewall":
            recommendations.append("Review and audit all firewall rules")
            recommendations.append("Remove unnecessary allow rules")
            recommendations.append("Enable firewall logging for blocked and allowed connections")
            recommendations.append("Implement network segmentation")
            recommendations.append("Use application-level firewalls for granular control")
            recommendations.append("Regular firewall rule reviews and cleanup")
            
        elif category == "eventlogs":
            recommendations.append("Correlate events across multiple log sources")
            recommendations.append("Investigate patterns of failed login attempts")
            recommendations.append("Review PowerShell script block logs for obfuscation")
            recommendations.append("Implement SIEM for real-time log monitoring")
            recommendations.append("Set up alerts for critical security events")
            recommendations.append("Maintain adequate log retention policies")
            
        return recommendations
        
    def get_external_resources(self, category, values):
        """Get relevant external intelligence resources"""
        resources = []
        
        # Common resources
        resources.append(("VirusTotal", URLS['virustotal']))
        resources.append(("Hybrid Analysis", URLS['hybrid_analysis']))
        resources.append(("MITRE ATT&CK", URLS['mitre_attack']))
        
        # Category-specific resources
        if category == "network":
            resources.append(("AbuseIPDB", URLS['abuseipdb']))
            resources.append(("ThreatConnect", URLS['threatconnect']))
        elif category == "process":
            resources.append(("Hybrid Analysis", URLS['hybrid_analysis']))
        elif category == "eventlogs":
            resources.append(("CISA Alerts", URLS['cisa_alerts']))
            resources.append(("CVE Database", URLS['cve_database']))
        elif category == "filesystem":
            resources.append(("ExploitDB", URLS['exploitdb']))
            
        return resources
        
    def filter_treeview(self, tree, search_text):
        """Filter treeview based on search text"""
        if not search_text:
            # Show all items
            for item in tree.get_children():
                tree.item(item, tags=())
            return
            
        search_text = search_text.lower()
        
        for item in tree.get_children():
            values = tree.item(item)['values']
            match = any(search_text in str(value).lower() for value in values)
            
            if match:
                tree.item(item, tags=())
            else:
                tree.item(item, tags=('hidden',))
                
    def clear_results(self):
        """Clear all results from treeviews"""
        trees = [
            self.network_tree, self.network_dns_tree, self.network_routing_tree,
            self.process_tree, self.process_high_cpu_tree, self.process_dll_tree,
            self.user_tree, self.user_admin_tree, self.user_priv_tree,
            self.persistence_tree, self.persistence_tasks_tree, self.persistence_services_tree, self.persistence_startup_tree,
            self.filesystem_tree, self.filesystem_recent_tree, self.filesystem_system_tree, self.filesystem_user_tree,
            self.firewall_tree, self.firewall_hosts_tree, self.firewall_adapters_tree,
            self.eventlogs_tree, self.eventlogs_success_tree, self.eventlogs_security_tree, self.eventlogs_system_tree, self.eventlogs_app_tree,
            self.system_tree, self.system_env_tree, self.system_software_tree, self.system_patches_tree
        ]
        
        for tree in trees:
            for item in tree.get_children():
                tree.delete(item)
                
        # Clear threats
        self.threats = {severity: [] for severity in SEVERITY_COLORS.keys()}
        self.update_threat_summary()
        
        # Hide critical alert and reset threat monitor
        self.hide_critical_alert()
        self.threat_level_label.config(text="SYSTEM STATUS: SECURE", fg='#00ff88')
        
        # Clear all threat tabs
        for category, threat_text in self.threat_texts.items():
            threat_text.config(state=tk.NORMAL)
            threat_text.delete(1.0, tk.END)
            threat_text.insert(tk.END, f"No {category.lower()} threats detected...")
            threat_text.config(state=tk.DISABLED)
        
        # Clear log
        self.log_text.delete(1.0, tk.END)
        
        self.log_message("Results cleared")
        
    def open_report_folder(self):
        """Open the report folder in Explorer"""
        os.startfile(LOG_DIR)
        
    def export_json(self):
        """Export results to JSON"""
        try:
            export_data = {
                'scan_date': datetime.now().isoformat(),
                'tool_version': APP_VERSION,
                'threats': self.threats,
                'summary': {
                    'critical': len(self.threats[SEVERITY_CRITICAL]),
                    'high': len(self.threats[SEVERITY_HIGH]),
                    'medium': len(self.threats[SEVERITY_MEDIUM]),
                    'low': len(self.threats[SEVERITY_LOW])
                }
            }
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                initialdir=os.path.expanduser("~")
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                self.log_message(f"Report exported to {file_path}")
                messagebox.showinfo("Export", f"Report exported successfully to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting report: {str(e)}")
            
    def export_csv(self):
        """Export results to CSV"""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialdir=os.path.expanduser("~")
            )
            
            if file_path:
                import csv
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Severity', 'Title', 'Description', 'Category', 'Timestamp'])
                    
                    for severity, threats in self.threats.items():
                        for threat in threats:
                            writer.writerow([
                                severity,
                                threat['title'],
                                threat['description'],
                                threat['category'],
                                threat['timestamp']
                            ])
                            
                self.log_message(f"Report exported to {file_path}")
                messagebox.showinfo("Export", f"Report exported successfully to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting report: {str(e)}")
            
    def export_pdf(self):
        """Export results to professional PDF report"""
        if not PDF_AVAILABLE:
            messagebox.showerror("PDF Export Error", 
                "PDF export requires the reportlab library. Install it with: pip install reportlab")
            return
            
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
                initialdir=os.path.expanduser("~")
            )
            
            if not file_path:
                return
                
            # Create PDF document
            doc = SimpleDocTemplate(file_path, pagesize=letter,
                                  rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = styles['Title']
            title_style.textColor = colors.HexColor('#00ff88')
            
            heading_style = styles['Heading1']
            heading_style.textColor = colors.HexColor('#00aaff')
            
            normal_style = styles['Normal']
            normal_style.textColor = colors.white
            
            # Build content
            content = []
            
            # Title page
            content.append(Paragraph(f"<font color='#00ff88'>{APP_TITLE}</font>", title_style))
            content.append(Spacer(1, 0.2*inch))
            content.append(Paragraph(f"<font color='#00aaff'>Version: {APP_VERSION}</font>", normal_style))
            content.append(Paragraph(f"<font color='#00aaff'>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font>", normal_style))
            content.append(Paragraph(f"<font color='#00aaff'>Created by: Hasan Ibrahim</font>", normal_style))
            content.append(Spacer(1, 0.5*inch))
            
            # Executive Summary
            content.append(Paragraph("<font color='#ff4444'>EXECUTIVE SUMMARY</font>", heading_style))
            content.append(Spacer(1, 0.1*inch))
            
            total_threats = sum(len(threats) for threats in self.threats.values())
            critical_count = len(self.threats[SEVERITY_CRITICAL])
            high_count = len(self.threats[SEVERITY_HIGH])
            medium_count = len(self.threats[SEVERITY_MEDIUM])
            low_count = len(self.threats[SEVERITY_LOW])
            
            summary_text = f"""
            <font color='white'>
            Total Threats Detected: {total_threats}<br/>
            Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}<br/>
            </font>
            """
            content.append(Paragraph(summary_text, normal_style))
            content.append(Spacer(1, 0.3*inch))
            
            # Threat Details by Severity
            for severity in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
                threats = self.threats[severity]
                if threats:
                    content.append(Paragraph(f"<font color='{SEVERITY_COLORS[severity]}'>{severity.upper()} THREATS ({len(threats)})</font>", heading_style))
                    content.append(Spacer(1, 0.1*inch))
                    
                    # Create table for threats
                    table_data = [['Title', 'Description', 'Category', 'Timestamp']]
                    for threat in threats:
                        table_data.append([
                            threat['title'],
                            threat['description'][:100] + '...' if len(threat['description']) > 100 else threat['description'],
                            threat['category'],
                            threat['timestamp']
                        ])
                    
                    table = Table(table_data, colWidths=[2*inch, 3*inch, 1.5*inch, 1.5*inch])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#1a1a2e')),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#0f3460')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#1a1a2e'), colors.HexColor('#16213e')]),
                    ]))
                    
                    content.append(table)
                    content.append(Spacer(1, 0.3*inch))
            
            # Recommendations
            content.append(PageBreak())
            content.append(Paragraph("<font color='#00ff88'>IMMEDIATE RECOMMENDATIONS</font>", heading_style))
            content.append(Spacer(1, 0.1*inch))
            
            if critical_count > 0:
                content.append(Paragraph("<font color='#ff4444'>CRITICAL ACTIONS REQUIRED:</font>", normal_style))
                content.append(Spacer(1, 0.05*inch))
                recommendations = [
                    "1. Immediately isolate affected systems from the network",
                    "2. Preserve forensic evidence before remediation",
                    "3. Review all critical threats and investigate root cause",
                    "4. Change all compromised credentials immediately",
                    "5. Scan systems with updated antivirus software",
                    "6. Review and update firewall rules",
                    "7. Monitor for additional suspicious activity"
                ]
                for rec in recommendations:
                    content.append(Paragraph(f"<font color='white'>{rec}</font>", normal_style))
                content.append(Spacer(1, 0.2*inch))
            
            # Footer
            content.append(PageBreak())
            content.append(Paragraph("<font color='#00aaff'>Report generated by Cyber Forensics Toolkit</font>", normal_style))
            content.append(Paragraph("<font color='#00aaff'>Created by Hasan Ibrahim</font>", normal_style))
            
            # Build PDF
            doc.build(content)
            
            self.log_message(f"PDF report exported to {file_path}")
            messagebox.showinfo("Export Success", f"Professional PDF report exported to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting PDF: {str(e)}")
        
    def compare_scans(self):
        """Compare with previous scan (placeholder)"""
        messagebox.showinfo("Compare Scans", "Historical comparison feature - to be implemented in future version.")
        
    def show_help(self):
        """Show help documentation"""
        help_text = f"""
{APP_TITLE}

This tool performs comprehensive security forensics scans on Windows systems.

FEATURES:
- Network Forensics: Analyzes connections, DNS cache, routing
- Process Analysis: Examines running processes and DLLs
- User Audit: Reviews user accounts and privileges
- Persistence Hunting: Scans startup, registry, services
- File System: Locates suspicious recently modified files
- Firewall Audit: Reviews firewall rules and hosts file
- Event Logs: Analyzes security events
- System Integrity: Performs system health checks

USAGE:
1. Click "Start Full Scan" to begin scanning
2. Monitor progress in the log window
3. Review results in each tab
4. Click items to view details and recommendations
5. Export reports as needed

For more information, visit: {URLS['microsoft_security']}
        """
        messagebox.showinfo("Help", help_text)
        
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
{APP_TITLE}
Version: {APP_VERSION}

A production-ready cyber forensics toolkit for Windows security analysis.

This tool helps identify security threats, suspicious activities,
and system vulnerabilities through comprehensive scanning and analysis.

New in v8.0 Enterprise Edition:
- Deep forensic artifact collection (Registry hives, Memory, MFT, Prefetch)
- Real-time monitoring daemon
- Telegram bot with remote command execution
- Rolling log display with download capability
- AI-powered threat detection framework
- Full Event Log export (Application, System, Security, PowerShell, etc.)

External Resources:
- VirusTotal: {URLS['virustotal']}
- MITRE ATT&CK: {URLS['mitre_attack']}
- CISA Alerts: {URLS['cisa_alerts']}
        """
        messagebox.showinfo("About", about_text)
    
    def open_telegram_settings(self):
        """Open Telegram bot configuration dialog"""
        if not TELEGRAM_AVAILABLE:
            messagebox.showerror(
                "Error",
                "python-telegram-bot not installed.\n\n"
                "Run: pip install python-telegram-bot==20.7"
            )
            return
        
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Telegram Bot Settings")
        settings_window.geometry("600x500")
        settings_window.configure(bg=COLOR_PANEL)
        
        # Title
        title_label = tk.Label(
            settings_window,
            text="🤖 Telegram Bot Configuration",
            font=('Consolas', 14, 'bold'),
            fg=COLOR_ACCENT_PRIMARY,
            bg=COLOR_PANEL
        )
        title_label.pack(pady=15)
        
        # Bot Token
        tk.Label(
            settings_window,
            text="Bot Token:",
            font=('Consolas', 10),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL
        ).pack(anchor='w', padx=20)
        
        token_entry = tk.Entry(
            settings_window,
            font=('Consolas', 9),
            bg=COLOR_GRID,
            fg=COLOR_TEXT,
            width=60
        )
        token_entry.insert(0, self.telegram_bot.config.get("bot_token", ""))
        token_entry.pack(padx=20, pady=5)
        
        # Authorized Chat IDs
        tk.Label(
            settings_window,
            text="Authorized Chat IDs (comma-separated):",
            font=('Consolas', 10),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL
        ).pack(anchor='w', padx=20, pady=(15, 0))
        
        auth_entry = tk.Entry(
            settings_window,
            font=('Consolas', 9),
            bg=COLOR_GRID,
            fg=COLOR_TEXT,
            width=60
        )
        auth_entry.insert(0, ','.join(self.telegram_bot.config.get("authorized_chat_ids", [])))
        auth_entry.pack(padx=20, pady=5)
        
        # Admin Chat IDs
        tk.Label(
            settings_window,
            text="Admin Chat IDs (comma-separated):",
            font=('Consolas', 10),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL
        ).pack(anchor='w', padx=20, pady=(15, 0))
        
        admin_entry = tk.Entry(
            settings_window,
            font=('Consolas', 9),
            bg=COLOR_GRID,
            fg=COLOR_TEXT,
            width=60
        )
        admin_entry.insert(0, ','.join(self.telegram_bot.config.get("admin_chat_ids", [])))
        admin_entry.pack(padx=20, pady=5)
        
        # Alert Settings
        alert_frame = tk.Frame(settings_window, bg=COLOR_PANEL)
        alert_frame.pack(pady=15, padx=20, fill='x')
        
        alert_enabled = tk.BooleanVar(value=self.telegram_bot.config.get("alert_enabled", True))
        tk.Checkbutton(
            alert_frame,
            text="Enable Alerts",
            variable=alert_enabled,
            font=('Consolas', 9),
            bg=COLOR_PANEL,
            fg=COLOR_TEXT,
            selectcolor=COLOR_GRID
        ).pack(anchor='w')
        
        # Log Auto-Delete Timeout
        tk.Label(
            settings_window,
            text="Log Auto-Delete Timeout (minutes):",
            font=('Consolas', 10),
            fg=COLOR_TEXT,
            bg=COLOR_PANEL
        ).pack(anchor='w', padx=20, pady=(15, 0))
        
        timeout_entry = tk.Entry(
            settings_window,
            font=('Consolas', 9),
            bg=COLOR_GRID,
            fg=COLOR_TEXT,
            width=10
        )
        timeout_entry.insert(0, str(self.telegram_bot.config.get("log_auto_delete_minutes", 5)))
        timeout_entry.pack(padx=20, pady=5)
        
        # Buttons
        button_frame = tk.Frame(settings_window, bg=COLOR_PANEL)
        button_frame.pack(pady=20)
        
        def save_settings():
            self.telegram_bot.config["bot_token"] = token_entry.get().strip()
            self.telegram_bot.config["authorized_chat_ids"] = [
                cid.strip() for cid in auth_entry.get().split(',') if cid.strip()
            ]
            self.telegram_bot.config["admin_chat_ids"] = [
                cid.strip() for cid in admin_entry.get().split(',') if cid.strip()
            ]
            self.telegram_bot.config["alert_enabled"] = alert_enabled.get()
            try:
                self.telegram_bot.config["log_auto_delete_minutes"] = int(timeout_entry.get())
            except ValueError:
                self.telegram_bot.config["log_auto_delete_minutes"] = 5
            
            self.telegram_bot.save_config()
            
            # Restart bot if token changed
            if self.telegram_bot.running:
                self.telegram_bot.stop_bot()
            
            if self.telegram_bot.config.get("bot_token"):
                self.telegram_bot.start_bot()
                messagebox.showinfo("Success", "Telegram Bot settings saved and bot restarted!")
            else:
                messagebox.showinfo("Success", "Settings saved (bot not started - no token)")
            settings_window.destroy()
        
        def test_bot():
            if not token_entry.get().strip():
                messagebox.showerror("Error", "Please enter a bot token first")
                return
            
            try:
                from telegram import Bot
                bot = Bot(token=token_entry.get().strip())
                bot.get_me()
                messagebox.showinfo("Success", "Bot token is valid!")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid bot token: {e}")
        
        tk.Button(
            button_frame,
            text="Test Token",
            command=test_bot,
            font=('Consolas', 9, 'bold'),
            bg=COLOR_ACCENT_SECONDARY,
            fg=COLOR_BACKGROUND,
            padx=15,
            pady=8,
            relief=tk.FLAT
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="Save",
            command=save_settings,
            font=('Consolas', 9, 'bold'),
            bg=COLOR_ACCENT_PRIMARY,
            fg=COLOR_BACKGROUND,
            padx=15,
            pady=8,
            relief=tk.FLAT
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="Cancel",
            command=settings_window.destroy,
            font=('Consolas', 9, 'bold'),
            bg=SEVERITY_COLORS[SEVERITY_HIGH],
            fg='white',
            padx=15,
            pady=8,
            relief=tk.FLAT
        ).pack(side=tk.LEFT, padx=5)
    
    def monitor_alert_callback(self, alert):
        """Callback for real-time monitoring alerts"""
        severity = alert.get('severity', 'Info')
        title = alert.get('title', 'Monitoring Alert')
        description = alert.get('description', '')
        category = alert.get('category', 'monitoring')
        
        # Add to threats
        self.add_threat(severity, title, description, category)
        
        # Log message
        self.log_message(f"[MONITOR] [{severity}] {title}: {description}")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if not MONITOR_AVAILABLE or not self.monitor:
            messagebox.showerror("Error", "Real-time monitoring module not available")
            return
        
        if self.monitoring_active:
            messagebox.showinfo("Info", "Monitoring is already active")
            return
        
        try:
            if self.monitor.start():
                self.monitoring_active = True
                self.log_message("✓ Real-time monitoring started")
                messagebox.showinfo("Success", "Real-time monitoring started successfully")
            else:
                messagebox.showerror("Error", "Failed to start monitoring")
        except Exception as e:
            messagebox.showerror("Error", f"Error starting monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if not MONITOR_AVAILABLE or not self.monitor:
            messagebox.showerror("Error", "Real-time monitoring module not available")
            return
        
        if not self.monitoring_active:
            messagebox.showinfo("Info", "Monitoring is not active")
            return
        
        try:
            self.monitor.stop()
            self.monitoring_active = False
            self.log_message("✓ Real-time monitoring stopped")
            messagebox.showinfo("Success", "Real-time monitoring stopped successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error stopping monitoring: {e}")
    
    def open_theme_settings(self):
        """Open theme settings dialog"""
        theme_window = tk.Toplevel(self.root)
        theme_window.title("Theme Settings")
        theme_window.geometry("500x400")
        theme_window.configure(bg=COLOR_PANEL)
        
        # Theme selection
        theme_frame = tk.Frame(theme_window, bg=COLOR_PANEL)
        theme_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(theme_frame, text="SELECT THEME:", font=('Consolas', 10, 'bold'),
                fg=COLOR_ACCENT_PRIMARY, bg=COLOR_PANEL).pack(anchor=tk.W)
        
        themes = ["Matrix", "Cyber", "Hacker", "Red Alert", "Stealth", "Dark Ops"]
        theme_var = tk.StringVar(value="Hacker")
        
        for theme in themes:
            rb = tk.Radiobutton(theme_frame, text=theme, variable=theme_var, value=theme,
                               font=('Consolas', 9), fg=COLOR_TEXT, bg=COLOR_PANEL,
                               selectcolor=COLOR_GRID, activebackground=COLOR_PANEL)
            rb.pack(anchor=tk.W, padx=20)
        
        # Apply button
        apply_button = tk.Button(theme_window, text="APPLY THEME", 
                                command=lambda: self.apply_theme(theme_var.get(), theme_window),
                                font=('Consolas', 10, 'bold'), bg=COLOR_ACCENT_PRIMARY, fg=COLOR_BACKGROUND,
                                padx=20, pady=10, relief=tk.FLAT, cursor='hand2')
        apply_button.pack(pady=20)
        
    def apply_theme(self, theme_name, window):
        """Apply selected theme"""
        global COLOR_ACCENT_PRIMARY, COLOR_ACCENT_SECONDARY, COLOR_CRITICAL, COLOR_GRID, COLOR_TEXT
        
        theme_configs = {
            "Matrix": {"primary": "#00FF00", "secondary": "#00FF00", "critical": "#FF0000", "grid": "#1a1a1a", "text": "#00FF00"},
            "Cyber": {"primary": "#00FFFF", "secondary": "#0088FF", "critical": "#FF0000", "grid": "#0a1a2a", "text": "#00FFFF"},
            "Hacker": {"primary": "#00FF00", "secondary": "#00FFFF", "critical": "#FF0000", "grid": "#1a1a1a", "text": "#00FF00"},
            "Red Alert": {"primary": "#FF0000", "secondary": "#FF6600", "critical": "#FF0000", "grid": "#2a0a0a", "text": "#FF0000"},
            "Stealth": {"primary": "#888888", "secondary": "#AAAAAA", "critical": "#FF0000", "grid": "#1a1a1a", "text": "#CCCCCC"},
            "Dark Ops": {"primary": "#00FF00", "secondary": "#008800", "critical": "#FF0000", "grid": "#0a0a0a", "text": "#00FF00"}
        }
        
        if theme_name in theme_configs:
            config = theme_configs[theme_name]
            COLOR_ACCENT_PRIMARY = config["primary"]
            COLOR_ACCENT_SECONDARY = config["secondary"]
            COLOR_CRITICAL = config["critical"]
            COLOR_GRID = config["grid"]
            COLOR_TEXT = config["text"]
            
            # Reapply styles
            self.setup_style()
            self.save_config()
            self.log_message(f"Theme changed to: {theme_name}")
            window.destroy()
            
    def reset_theme(self):
        """Reset to default hacker theme"""
        global COLOR_ACCENT_PRIMARY, COLOR_ACCENT_SECONDARY, COLOR_CRITICAL, COLOR_GRID, COLOR_TEXT
        
        COLOR_ACCENT_PRIMARY = "#00FF00"
        COLOR_ACCENT_SECONDARY = "#00FFFF"
        COLOR_CRITICAL = "#FF0000"
        COLOR_GRID = "#1a1a1a"
        COLOR_TEXT = "#00FF00"
        
        self.setup_style()
        self.save_config()
        self.log_message("Theme reset to default")
        
    def load_config(self):
        """Load configuration from file"""
        global COLOR_ACCENT_PRIMARY, COLOR_ACCENT_SECONDARY, COLOR_CRITICAL, COLOR_GRID, COLOR_TEXT
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    
                # Load theme colors
                if 'theme' in config:
                    theme = config['theme']
                    COLOR_ACCENT_PRIMARY = theme.get('accent_primary', COLOR_ACCENT_PRIMARY)
                    COLOR_ACCENT_SECONDARY = theme.get('accent_secondary', COLOR_ACCENT_SECONDARY)
                    COLOR_CRITICAL = theme.get('critical', COLOR_CRITICAL)
                    COLOR_GRID = theme.get('grid', COLOR_GRID)
                    COLOR_TEXT = theme.get('text', COLOR_TEXT)
                    
                self.log_message("Configuration loaded successfully")
                
        except Exception as e:
            self.log_message(f"Error loading configuration: {str(e)}")
            
    def save_config(self):
        """Save configuration to file"""
        global COLOR_ACCENT_PRIMARY, COLOR_ACCENT_SECONDARY, COLOR_CRITICAL, COLOR_GRID, COLOR_TEXT
        
        try:
            config = {
                'theme': {
                    'accent_primary': COLOR_ACCENT_PRIMARY,
                    'accent_secondary': COLOR_ACCENT_SECONDARY,
                    'critical': COLOR_CRITICAL,
                    'grid': COLOR_GRID,
                    'text': COLOR_TEXT
                },
                'version': APP_VERSION,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
                
            self.log_message("Configuration saved successfully")
            
        except Exception as e:
            self.log_message(f"Error saving configuration: {str(e)}")
        
    def search_virustotal(self):
        """Open VirusTotal in browser"""
        import webbrowser
        webbrowser.open(URLS['virustotal'])
        
    def open_in_browser(self):
        """Open selected item in browser (placeholder)"""
        messagebox.showinfo("Open in Browser", "Feature to be implemented based on selected item type.")
        
    def copy_to_clipboard(self):
        """Copy selected item details to clipboard"""
        self.detail_text.config(state=tk.NORMAL)
        text = self.detail_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.detail_text.config(state=tk.DISABLED)
        messagebox.showinfo("Copied", "Details copied to clipboard")
        
    def mark_false_positive(self):
        """Mark selected item as false positive (placeholder)"""
        messagebox.showinfo("False Positive", "False positive marking feature - to be implemented.")


def is_admin():
    """Check if the script is running with admin privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def main():
    """Main entry point"""
    # Check for admin privileges and request if needed
    if not is_admin():
        try:
            import ctypes
            # Request admin privileges
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            return
        except:
            pass
    
    # Create and run application
    root = tk.Tk()
    app = CyberForensicsApp(root)
    
    # Handle window close properly
    def on_closing():
        app.animation_running = False
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.detail_text.config(state=tk.DISABLED)
        messagebox.showinfo("Copied", "Details copied to clipboard")
        
    def mark_false_positive(self):
        """Mark selected item as false positive (placeholder)"""
        messagebox.showinfo("False Positive", "False positive marking feature - to be implemented.")


def is_admin():
    """Check if the script is running with admin privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def main():
    """Main entry point"""
    # Check for admin privileges and request if needed
    if not is_admin():
        try:
            import ctypes
            # Request admin privileges
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            return
        except:
            pass
    
    # Create and run application
    root = tk.Tk()
    app = CyberForensicsApp(root)
    
    # Handle window close properly
    def on_closing():
        app.animation_running = False
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
