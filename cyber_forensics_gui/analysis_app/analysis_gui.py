#!/usr/bin/env python3
"""
User-Friendly Analysis GUI for Cyber Forensics Toolkit v8.0
Presents forensic findings in an easy-to-understand format for end users
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
from datetime import datetime
from report_analyzer import ReportAnalyzer


class AnalysisApp:
    """User-friendly forensic analysis application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Forensics Report Analyzer - v8.0")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        
        # Colors
        self.colors = {
            'bg': '#f0f0f0',
            'header': '#2c3e50',
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#27ae60',
            'info': '#3498db',
            'white': '#ffffff',
            'gray': '#ecf0f1'
        }
        
        self.analyzer = ReportAnalyzer()
        self.current_results = None
        
        self.create_gui()
    
    def create_gui(self):
        """Create the main GUI"""
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['header'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Cyber Forensics Report Analyzer",
            font=('Arial', 20, 'bold'),
            bg=self.colors['header'],
            fg=self.colors['white']
        )
        title_label.pack(pady=20)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Analyze your forensic reports in plain language",
            font=('Arial', 10),
            bg=self.colors['header'],
            fg=self.colors['gray']
        )
        subtitle_label.pack()
        
        # Main content
        content_frame = tk.Frame(self.root, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Control panel
        control_frame = tk.Frame(content_frame, bg=self.colors['bg'])
        control_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            control_frame,
            text="Report Location:",
            font=('Arial', 11),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        self.report_path_var = tk.StringVar(value=os.path.join(
            os.path.expanduser("~"),
            "Desktop",
            "Cyber_Forensic_Report"
        ))
        
        path_entry = tk.Entry(
            control_frame,
            textvariable=self.report_path_var,
            font=('Arial', 10),
            width=50
        )
        path_entry.pack(side=tk.LEFT, padx=10)
        
        analyze_button = tk.Button(
            control_frame,
            text="🔎 Analyze Reports",
            command=self.analyze_reports,
            font=('Arial', 11, 'bold'),
            bg=self.colors['info'],
            fg=self.colors['white'],
            padx=20,
            pady=10,
            relief=tk.FLAT
        )
        analyze_button.pack(side=tk.LEFT, padx=10)
        
        browse_button = tk.Button(
            control_frame,
            text="📁 Browse",
            command=self.browse_directory,
            font=('Arial', 10),
            bg=self.colors['gray'],
            relief=tk.FLAT
        )
        browse_button.pack(side=tk.LEFT)
        
        # Summary cards
        self.summary_frame = tk.Frame(content_frame, bg=self.colors['bg'])
        self.summary_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.create_summary_cards()
        
        # Findings notebook
        notebook = ttk.Notebook(content_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Critical findings tab
        self.critical_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.critical_frame, text="🔴 Critical")
        self.create_findings_tab(self.critical_frame, 'critical')
        
        # High findings tab
        self.high_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.high_frame, text="🟠 High")
        self.create_findings_tab(self.high_frame, 'high')
        
        # Medium findings tab
        self.medium_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.medium_frame, text="🟡 Medium")
        self.create_findings_tab(self.medium_frame, 'medium')
        
        # Low findings tab
        self.low_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.low_frame, text="🟢 Low")
        self.create_findings_tab(self.low_frame, 'low')
        
        # Info tab
        self.info_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.info_frame, text="🔵 Info")
        self.create_findings_tab(self.info_frame, 'info')
        
        # Recommendations tab
        self.recommendations_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.recommendations_frame, text="💡 Recommendations")
        self.create_recommendations_tab()
        
        # Detailed View tab
        self.details_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.details_frame, text="📋 Detailed View")
        self.create_details_tab()
        
        # Raw Data tab
        self.raw_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.raw_frame, text="📄 Raw Data")
        self.create_raw_data_tab()
        
        # Export tab
        self.export_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.export_frame, text="💾 Export")
        self.create_export_tab()
        
        # Timeline tab
        self.timeline_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.timeline_frame, text="📅 Timeline")
        self.create_timeline_tab()
        
        # Category Breakdown tab
        self.category_frame = tk.Frame(notebook, bg=self.colors['bg'])
        notebook.add(self.category_frame, text="📊 Categories")
        self.create_category_tab()
    
    def create_summary_cards(self):
        """Create summary cards showing statistics"""
        self.summary_labels = {}
        
        severities = [
            ('critical', 'Critical Issues', self.colors['critical']),
            ('high', 'High Issues', self.colors['high']),
            ('medium', 'Medium Issues', self.colors['medium']),
            ('low', 'Low Issues', self.colors['low']),
            ('info', 'Info Items', self.colors['info'])
        ]
        
        for i, (severity, label, color) in enumerate(severities):
            card = tk.Frame(
                self.summary_frame,
                bg=self.colors['white'],
                relief=tk.RAISED,
                bd=1
            )
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            tk.Label(
                card,
                text=label,
                font=('Arial', 10),
                bg=self.colors['white'],
                fg='#7f8c8d'
            ).pack(pady=(10, 5))
            
            count_label = tk.Label(
                card,
                text="0",
                font=('Arial', 24, 'bold'),
                bg=self.colors['white'],
                fg=color
            )
            count_label.pack(pady=(0, 10))
            
            self.summary_labels[severity] = count_label
    
    def create_findings_tab(self, parent, severity):
        """Create a findings tab"""
        # Header
        header = tk.Frame(parent, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text=f"{severity.capitalize()} Severity Findings",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        # Findings list
        list_frame = tk.Frame(parent, bg=self.colors['white'], relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = scrolledtext.ScrolledText(
            list_frame,
            wrap=tk.WORD,
            font=('Arial', 10),
            bg=self.colors['white'],
            yscrollcommand=scrollbar.set
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        setattr(self, f'{severity}_text', text_widget)
    
    def create_recommendations_tab(self):
        """Create recommendations tab"""
        header = tk.Frame(self.recommendations_frame, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text="Recommended Actions",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        list_frame = tk.Frame(self.recommendations_frame, bg=self.colors['white'], relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.recommendations_text = scrolledtext.ScrolledText(
            list_frame,
            wrap=tk.WORD,
            font=('Arial', 10),
            bg=self.colors['white'],
            yscrollcommand=scrollbar.set
        )
        self.recommendations_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.recommendations_text.yview)
    
    def create_details_tab(self):
        """Create detailed view tab with all findings"""
        header = tk.Frame(self.details_frame, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text="Detailed Findings View",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        # Filter frame
        filter_frame = tk.Frame(header, bg=self.colors['bg'])
        filter_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(
            filter_frame,
            text="Filter by Category:",
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        self.category_filter = tk.StringVar(value="All")
        categories = ["All", "Network", "Process", "User", "Persistence", "File System", "Security", "Registry", "Memory", "Artifacts"]
        category_menu = ttk.OptionMenu(filter_frame, self.category_filter, "All", *categories)
        category_menu.pack(side=tk.LEFT, padx=5)
        
        # Details text widget
        list_frame = tk.Frame(self.details_frame, bg=self.colors['white'], relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.details_text = scrolledtext.ScrolledText(
            list_frame,
            wrap=tk.WORD,
            font=('Arial', 10),
            bg=self.colors['white'],
            yscrollcommand=scrollbar.set
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.details_text.yview)
    
    def create_raw_data_tab(self):
        """Create raw data viewer tab"""
        header = tk.Frame(self.raw_frame, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text="Raw Report Data",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        # File selector
        file_frame = tk.Frame(header, bg=self.colors['bg'])
        file_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(
            file_frame,
            text="Select File:",
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        self.raw_file_var = tk.StringVar()
        self.raw_file_combo = ttk.Combobox(file_frame, textvariable=self.raw_file_var, width=40)
        self.raw_file_combo.pack(side=tk.LEFT, padx=5)
        
        view_button = tk.Button(
            file_frame,
            text="View",
            command=self.view_raw_file,
            font=('Arial', 9),
            bg=self.colors['info'],
            fg=self.colors['white'],
            relief=tk.FLAT
        )
        view_button.pack(side=tk.LEFT, padx=5)
        
        # Raw data text widget
        list_frame = tk.Frame(self.raw_frame, bg=self.colors['white'], relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.raw_text = scrolledtext.ScrolledText(
            list_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg=self.colors['white'],
            yscrollcommand=scrollbar.set
        )
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.raw_text.yview)
    
    def create_export_tab(self):
        """Create export tab"""
        header = tk.Frame(self.export_frame, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text="Export Analysis Results",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        # Export options frame
        options_frame = tk.Frame(self.export_frame, bg=self.colors['bg'])
        options_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Export format
        format_frame = tk.Frame(options_frame, bg=self.colors['bg'])
        format_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            format_frame,
            text="Export Format:",
            font=('Arial', 11),
            bg=self.colors['bg'],
            width=15,
            anchor='w'
        ).pack(side=tk.LEFT)
        
        self.export_format = tk.StringVar(value="TXT")
        formats = ["TXT", "JSON", "HTML"]
        for fmt in formats:
            tk.Radiobutton(
                format_frame,
                text=fmt,
                variable=self.export_format,
                value=fmt,
                bg=self.colors['bg']
            ).pack(side=tk.LEFT, padx=10)
        
        # Include raw data option
        self.include_raw = tk.BooleanVar(value=False)
        tk.Checkbutton(
            options_frame,
            text="Include raw report data in export",
            variable=self.include_raw,
            bg=self.colors['bg'],
            font=('Arial', 10)
        ).pack(anchor='w', pady=10)
        
        # Export button
        export_button = tk.Button(
            options_frame,
            text="💾 Export Analysis",
            command=self.export_analysis,
            font=('Arial', 12, 'bold'),
            bg=self.colors['info'],
            fg=self.colors['white'],
            padx=30,
            pady=15,
            relief=tk.FLAT
        )
        export_button.pack(pady=20)
    
    def browse_directory(self):
        """Browse for report directory"""
        from tkinter import filedialog
        directory = filedialog.askdirectory()
        if directory:
            self.report_path_var.set(directory)
    
    def analyze_reports(self):
        """Analyze reports and display results"""
        report_dir = self.report_path_var.get()
        
        if not os.path.exists(report_dir):
            messagebox.showerror("Error", f"Report directory not found: {report_dir}")
            return
        
        # Update analyzer path
        self.analyzer.report_dir = report_dir
        
        # Analyze
        self.current_results = self.analyzer.analyze_reports()
        
        if 'error' in self.current_results:
            messagebox.showerror("Error", self.current_results['error'])
            return
        
        # Update summary cards
        for severity, count in self.current_results['findings_by_severity'].items():
            self.summary_labels[severity].config(text=str(count))
        
        # Update findings tabs
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            text_widget = getattr(self, f'{severity}_text')
            text_widget.delete(1.0, tk.END)
            
            findings = self.current_results['findings'][severity]
            if not findings:
                text_widget.insert(tk.END, f"No {severity} severity findings.\n")
            else:
                for i, finding in enumerate(findings, 1):
                    text_widget.insert(tk.END, f"\n{'='*60}\n")
                    text_widget.insert(tk.END, f"Finding #{i}\n")
                    text_widget.insert(tk.END, f"{'='*60}\n\n")
                    text_widget.insert(tk.END, f"Category: {finding['category']}\n")
                    text_widget.insert(tk.END, f"Title: {finding['title']}\n\n")
                    text_widget.insert(tk.END, f"What happened:\n")
                    text_widget.insert(tk.END, f"{finding['description']}\n\n")
                    text_widget.insert(tk.END, f"What you should do:\n")
                    text_widget.insert(tk.END, f"{finding['recommendation']}\n\n")
        
        # Update detailed view
        self.update_details_view()
        
        # Update raw file list
        self.update_raw_file_list()
        
        # Update recommendations
        self.recommendations_text.delete(1.0, tk.END)
        for i, rec in enumerate(self.current_results['recommendations'], 1):
            self.recommendations_text.insert(tk.END, f"\n{'='*60}\n")
            self.recommendations_text.insert(tk.END, f"Priority: {rec['priority']}\n")
            self.recommendations_text.insert(tk.END, f"{'='*60}\n\n")
            self.recommendations_text.insert(tk.END, f"Action: {rec['action']}\n")
            self.recommendations_text.insert(tk.END, f"Details: {rec['details']}\n\n")
        ile_list()
        
        # Update tmein
        self.updatetimene_view()
        
        # Update category breakdown
        elf.update_caegory_view
        messagebox.showinfo(
            "Analysis Complete",
            f"Analysis complete!\n\nTotal findings: {self.current_results['total_findings']}"
        )
    
    def update_details_view(self):
        """Update detailed view with all findings"""
        self.details_text.delete(1.0, tk.END)
        
        filter_category = self.category_filter.get()
        
        all_findings = []
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            for finding in self.current_results['findings'][severity]:
                finding['severity'] = severity
                all_findings.append(finding)
        
        # Filter by category if selected
        if filter_category != "All":
            all_findings = [f for f in all_findings if f['category'] == filter_category]
        
        if not all_findings:
            self.details_text.insert(tk.END, f"No findings to display.\n")
            return
        
        # Group by category
        categories = {}
        for finding in all_findings:
            cat = finding['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(finding)
        
        # Display by category
        for category, findings in categories.items():
            self.details_text.insert(tk.END, f"\n{'='*70}\n")
            self.details_text.insert(tk.END, f"CATEGORY: {category.upper()}\n")
            self.details_text.insert(tk.END, f"{'='*70}\n\n")
            
            for i, finding in enumerate(findings, 1):
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢',
                    'info': '🔵'
                }.get(finding['severity'], '⚪')
                
                self.details_text.insert(tk.END, f"\n{severity_emoji} Finding #{i} [{finding['severity'].upper()}]\n")
                self.details_text.insert(tk.END, f"{'-'*70}\n")
                self.details_text.insert(tk.END, f"Title: {finding['title']}\n\n")
                self.details_text.insert(tk.END, f"Description:\n{finding['description']}\n\n")
                self.details_text.insert(tk.END, f"Recommendation:\n{finding['recommendation']}\n\n")
    
    def update_raw_file_list(self):
        """Update raw file list combobox"""
        report_dir = self.report_path_var.get()
        
        if not os.path.exists(report_dir):
            return
        
        raw_files = []
        
        # Get all text files
        for root, dirs, files in os.walk(report_dir):
            for file in files:
                if file.endswith('.txt') or file.endswith('.log'):
                    rel_path = os.path.relpath(os.path.join(root, file), report_dir)
                    raw_files.append(rel_path)
        
        # Get hive files
        registry_dir = os.path.join(report_dir, "REGISTRY")
        if os.path.exists(registry_dir):
            for file in os.listdir(registry_dir):
                if file.endswith('.hive'):
                    raw_files.append(f"REGISTRY/{file}")
        
        # Get evtx files
        eventlogs_dir = os.path.join(report_dir, "EVENTLOGS")
        if os.path.exists(eventlogs_dir):
            for file in os.listdir(eventlogs_dir):
                if file.endswith('.evtx'):
                    raw_files.append(f"EVENTLOGS/{file}")
        
        raw_files.sort()
        self.raw_file_combo['values'] = raw_files
        if raw_files:
            self.raw_file_var.set(raw_files[0])
    
    def view_raw_file(self):
        """View selected raw file"""
        file_path = self.raw_file_var.get()
        if not file_path:
            return
        
        full_path = os.path.join(self.report_path_var.get(), file_path)
        
        if not os.path.exists(full_path):
            self.raw_text.delete(1.0, tk.END)
            self.raw_text.insert(tk.END, f"File not found: {full_path}\n")
            return
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            self.raw_text.delete(1.0, tk.END)
            self.raw_text.insert(tk.END, f"File: {file_path}\n")
            self.raw_text.insert(tk.END, f"Path: {full_path}\n")
            self.raw_text.insert(tk.END, f"Size: {len(content)} bytes\n")
            self.raw_text.insert(tk.END, f"{'='*70}\n\n")
            self.raw_text.insert(tk.END, content)
            
        except Exception as e:
            self.raw_text.delete(1.0, tk.END)
            self.raw_text.insert(tk.END, f"Error reading file: {e}\n")
    
    def update_timeline_view(self):
        """Update timeline view with chronological findings"""
        self.timeline_text.delete(1.0, tk.END)
        
        self.timeline_text.insert(tk.END, f"{'='*70}\n")
        self.timeline_text.insert(tk.END, f"ANALYSIS TIMELINE\n")
        self.timeline_text.insert(tk.END, f"{'='*70}\n\n")
        self.timeline_text.insert(tk.END, f"Analysis Date: {self.current_results['timestamp']}\n")
        self.timeline_text.insert(tk.END, f"Report Directory: {self.current_results['report_directory']}\n\n")
        
        # Display findings in severity order (simulating timeline)
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            findings = self.current_results['findings'][severity]
            if findings:
                self.timeline_text.insert(tk.END, f"\n{'='*70}\n")
                self.timeline_text.insert(tk.END, f"PHASE: {severity.upper()} PRIORITY FINDINGS\n")
                self.timeline_text.insert(tk.END, f"{'='*70}\n\n")
                
                for i, finding in enumerate(findings, 1):
                    self.timeline_text.insert(tk.END, f"[{i}] {finding['category']}: {finding['title']}\n")
                    self.timeline_text.insert(tk.END, f"    {finding['description']}\n")
                    self.timeline_text.insert(tk.END, f"    Action: {finding['recommendation']}\n\n")
    
    def update_category_view(self):
        """Update category breakdown view"""
        self.category_text.delete(1.0, tk.END)
        
        # Group findings by category
        category_stats = defaultdict(lambda: {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0})
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            for finding in self.current_results['findings'][severity]:
                cat = finding['category']
                category_stats[cat][severity] += 1
                category_stats[cat]['total'] += 1
        
        # Sort by total findings
        sorted_categories = sorted(category_stats.items(), key=lambda x: x[1]['total'], reverse=True)
        
        self.category_text.insert(tk.END, f"{'='*70}\n")
        self.category_text.insert(tk.END, f"FINDINGS BY CATEGORY\n")
        self.category_text.insert(tk.END, f"{'='*70}\n\n")
        
        for category, stats in sorted_categories:
            self.category_text.insert(tk.END, f"\n{'='*70}\n")
            self.category_text.insert(tk.END, f"CATEGORY: {category.upper()}\n")
            self.category_text.insert(tk.END, f"{'='*70}\n")
            self.category_text.insert(tk.END, f"Total Findings: {stats['total']}\n")
            self.category_text.insert(tk.END, f"  🔴 Critical: {stats['critical']}\n")
            self.category_text.insert(tk.END, f"  🟠 High: {stats['high']}\n")
            self.category_text.insert(tk.END, f"  🟡 Medium: {stats['medium']}\n")
            self.category_text.insert(tk.END, f"  🟢 Low: {stats['low']}\n")
            self.category_text.insert(tk.END, f"  🔵 Info: {stats['info']}\n\n")
            
            # Show top findings in this category
            category_findings = []
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                for finding in self.current_results['findings'][severity]:
                    if finding['category'] == category:
                        category_findings.append((severity, finding))
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            category_findings.sort(key=lambda x: severity_order.get(x[0], 5))
            
            if category_findings:
                self.category_text.insert(tk.END, f"Top Findings in this category:\n")
                self.category_text.insert(tk.END, f"{'-'*70}\n")
                for severity, finding in category_findings[:5]:  # Show top 5
                    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(severity, '⚪')
                    self.category_text.insert(tk.END, f"{emoji} {finding['title']}\n")
                self.category_text.insert(tk.END, "\n")
    
    def export_analysis(self):
        """Export analysis results"""
        from tkinter import filedialog
        
        export_format = self.export_format.get()
        
        if export_format == "TXT":
            default_ext = ".txt"
            filetypes = [("Text Files", "*.txt")]
        elif export_format == "JSON":
            default_ext = ".json"
            filetypes = [("JSON Files", "*.json")]
        else:  # HTML
            default_ext = ".html"
            filetypes = [("HTML Files", "*.html")]
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=filetypes,
            title="Export Analysis Results"
        )
        
        if not file_path:
            return
        
        try:
            if export_format == "TXT":
                self.export_txt(file_path)
            elif export_format == "JSON":
                self.export_json(file_path)
            else:
                self.export_html(file_path)
            
            messagebox.showinfo("Export Complete", f"Analysis exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting analysis:\n{e}")
    
    def export_txt(self, file_path):
        """Export to TXT format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("CYBER FORENSICS ANALYSIS REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Analysis Date: {self.current_results['timestamp']}\n")
            f.write(f"Report Directory: {self.current_results['report_directory']}\n")
            f.write(f"Total Findings: {self.current_results['total_findings']}\n\n")
            
            f.write("FINDINGS BY SEVERITY\n")
            f.write("="*70 + "\n\n")
            for severity, count in self.current_results['findings_by_severity'].items():
                f.write(f"{severity.capitalize()}: {count}\n")
            
            f.write("\n\nDETAILED FINDINGS\n")
            f.write("="*70 + "\n\n")
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                findings = self.current_results['findings'][severity]
                if findings:
                    f.write(f"\n{severity.upper()} SEVERITY\n")
                    f.write("-"*70 + "\n\n")
                    for i, finding in enumerate(findings, 1):
                        f.write(f"Finding #{i}\n")
                        f.write(f"Category: {finding['category']}\n")
                        f.write(f"Title: {finding['title']}\n")
                        f.write(f"Description: {finding['description']}\n")
                        f.write(f"Recommendation: {finding['recommendation']}\n\n")
            
            f.write("\n\nRECOMMENDATIONS\n")
            f.write("="*70 + "\n\n")
            for rec in self.current_results['recommendations']:
                f.write(f"Priority: {rec['priority']}\n")
                f.write(f"Action: {rec['action']}\n")
                f.write(f"Details: {rec['details']}\n\n")
    
    def export_json(self, file_path):
        """Export to JSON format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.current_results, f, indent=2, default=str)
    
    def export_html(self, file_path):
        """Export to HTML format"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Forensics Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ background: #fff; border-left: 4px solid #3498db; padding: 15px; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f39c12; }}
        .low {{ border-left-color: #27ae60; }}
        .info {{ border-left-color: #3498db; }}
        .recommendation {{ background: #d5f5e3; padding: 15px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Cyber Forensics Analysis Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Analysis Date:</strong> {self.current_results['timestamp']}</p>
            <p><strong>Report Directory:</strong> {self.current_results['report_directory']}</p>
            <p><strong>Total Findings:</strong> {self.current_results['total_findings']}</p>
        </div>
        
        <h2>Findings by Severity</h2>
"""
        for severity, count in self.current_results['findings_by_severity'].items():
            html += f"<p><strong>{severity.capitalize()}:</strong> {count}</p>"
        
        html += "<h2>Detailed Findings</h2>\n"
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = self.current_results['findings'][severity]
            if findings:
                html += f"<h3>{severity.upper()} Severity</h3>\n"
                for finding in findings:
                    html += f"""
        <div class="finding {severity}">
            <h4>{finding['title']}</h4>
            <p><strong>Category:</strong> {finding['category']}</p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
        </div>
"""
        
        html += "<h2>Recommendations</h2>\n"
        for rec in self.current_results['recommendations']:
            html += f"""
        <div class="recommendation">
            <h4>Priority: {rec['priority']}</h4>
            <p><strong>Action:</strong> {rec['action']}</p>
            <p><strong>Details:</strong> {rec['details']}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def create_timeline_tab(self):
        """Create timeline view tab"""
        header = tk.Frame(self.timeline_frame, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text="Analysis Timeline",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        # Timeline text widget
        list_frame = tk.Frame(self.timeline_frame, bg=self.colors['white'], relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.timeline_text = scrolledtext.ScrolledText(
            list_frame,
            wrap=tk.WORD,
            font=('Arial', 10),
            bg=self.colors['white'],
            yscrollcommand=scrollbar.set
        )
        self.timeline_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.timeline_text.yview)
    
    def create_category_tab(self):
        """Create category breakdown tab"""
        header = tk.Frame(self.category_frame, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(
            header,
            text="Findings by Category",
            font=('Arial', 14, 'bold'),
            bg=self.colors['bg']
        ).pack(side=tk.LEFT)
        
        # Category text widget
        list_frame = tk.Frame(self.category_frame, bg=self.colors['white'], relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.category_text = scrolledtext.ScrolledText(
            list_frame,
            wrap=tk.WORD,
            font=('Arial', 10),
            bg=self.colors['white'],
            yscrollcommand=scrollbar.set
        )
        self.category_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.category_text.yview)


def main():
    root = tk.Tk()
    app = AnalysisApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
