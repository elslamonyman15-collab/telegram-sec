# Cyber Forensics Toolkit v8.0 - Enterprise Edition

A production-ready GUI application for Windows security forensics and threat analysis. This tool converts the original 2.bat batch script into a modern, user-friendly tkinter application with advanced threat detection, severity scoring, detailed recommendations, Telegram bot integration, and AI-powered anomaly detection.

## Features

### 🔍 Comprehensive Security Scanning
- **Network Forensics**: Analyzes active connections, DNS cache, routing tables, and ARP cache
- **Process Anatomy**: Examines running processes, DLLs, modules, and high CPU usage
- **User Discovery**: Audits local user accounts, admin privileges, and active sessions
- **Persistence Hunting**: Scans startup items, registry keys, scheduled tasks, and services
- **File System Forensics**: Locates recently modified executable files in critical directories
- **Firewall & Hosts**: Audits firewall rules and hosts file integrity
- **Security Event Logs**: Analyzes failed/successful logins and PowerShell events
- **System Integrity**: Performs cache cleanup and system health checks

### 🎨 Modern GUI Interface
- **Tabbed Interface**: 8 organized tabs for each scan category
- **Real-time Progress**: Live progress bar with step-by-step status updates
- **Live Log Window**: Real-time command output and scan status
- **Sortable Tables**: Click column headers to sort data
- **Search & Filter**: Filter results across all tabs
- **Color-coded Severity**: Critical (Red), High (Orange), Medium (Yellow), Low (Green), Info (Blue)
- **Detail Panel**: Side panel showing detailed information for selected items

### 🚨 Automatic Threat Detection
- **Severity Scoring**: Automatic assessment of findings (Critical/High/Medium/Low/Info)
- **Threat Dashboard**: Real-time threat count display in the header
- **Pattern Matching**: Identifies suspicious processes, files, and network connections
- **Persistence Detection**: Finds hidden startup items and suspicious registry entries

### 📋 Intelligent Recommendations
- **Context-aware Remediation**: Specific recommendations for each threat type
- **External URL References**: Links to VirusTotal, MITRE ATT&CK, CISA, and more
- **Actionable Steps**: Clear guidance on what to do next
- **False Positive Marking**: Ability to mark items as false positives

### 🤖 Telegram Bot Integration
- **Remote Command Execution**: Execute forensic scans and commands via Telegram
- **Live Alerts**: Real-time threat notifications to authorized users
- **Rolling Log Display**: Watch command output in real-time with auto-deletion
- **Log Download**: Download command logs as files
- **Admin Controls**: Kill processes, block IPs, execute custom commands (admin only)
- **Authorization System**: Whitelist authorized chat IDs with role-based access

### 📁 Organized Reporting
- **Structured Folder Hierarchy**: 9 categorized subdirectories for organized reports
- **Executive Summary**: High-level overview with threat counts and recommendations
- **Multiple Export Formats**: JSON, CSV, and PDF export options
- **Detailed Logs**: Raw data saved for forensic analysis

## Installation

### Prerequisites
- Windows 10/11
- Python 3.7 or higher
- Administrator privileges (required for system scans)

### Setup
1. Download `cyber_forensics_gui.py`
2. Ensure Python is installed and in your PATH
3. Run the application:
   ```bash
   python cyber_forensics_gui.py
   ```

The application will automatically request administrator privileges if not already running with elevated permissions.

## Usage

### Starting a Scan
1. Click the **"▶ Start Full Scan"** button in the top control panel
2. Monitor the progress bar and live log window
3. Results will appear in real-time in each tab
4. The scan runs in the background, so the UI remains responsive

### Reviewing Results
- **Click on any tab** to view results for that category
- **Click on any item** in the table to view detailed information in the side panel
- **Use the search box** above each table to filter results
- **Click column headers** to sort the data

### Taking Action
- **Select an item** and view recommendations in the detail panel
- **Click "🔍 Search VirusTotal"** to open VirusTotal in your browser
- **Click "📋 Copy to Clipboard"** to copy item details
- **Click "⚠️ Mark as False Positive"** to mark items (feature in development)

### Telegram Bot Setup
1. **Create a Telegram Bot:**
   - Message @BotFather on Telegram
   - Send `/newbot` and follow instructions
   - Copy the bot token
2. **Configure in GUI:**
   - Go to Tools → Telegram Bot Settings
   - Enter your bot token
   - Add your Telegram chat ID (message @userinfobot to get your ID)
   - Add admin chat IDs for elevated privileges
   - Click "Test Token" to verify
   - Click "Save" to apply settings
3. **Use Telegram Commands:**
   - `/status` - Check system status
   - `/scan` - Trigger full scan
   - `/processes` - List running processes
   - `/connections` - List network connections
   - `/exec <command>` - Execute custom command (admin only)
   - `/kill <pid>` - Terminate process (admin only)
   - `/help` - Show all commands

### Exporting Reports
- **Click "📄 Export Report"** to export findings
- Choose from JSON (machine-readable), CSV (spreadsheet), or PDF formats
- Reports are saved to your chosen location
- All raw data is also saved to `Desktop\Cyber_Forensic_Report`

### Opening Report Folder
- Click **Tools → Open Report Folder** to open the report directory in Explorer
- Reports are organized by category in subdirectories

## Threat Severity Levels

### 🔴 Critical (Red)
**Immediate action required - System likely compromised**
- Processes running from temp directories
- Executable files in system folders modified within 24 hours
- Scheduled tasks from temp locations
- Registry run keys pointing to temp directories
- Multiple failed login attempts (brute force)

### 🟠 High (Orange)
**Strong indicators of compromise - Investigate immediately**
- Unknown foreign IP connections
- Suspicious DNS queries
- Processes with no digital signature
- User accounts without passwords
- Suspicious startup entries
- Non-Microsoft services with suspicious names

### 🟡 Medium (Yellow)
**Suspicious activity - Requires investigation**
- Established connections on non-standard ports
- High CPU usage from unknown processes
- Recently created admin accounts
- Unknown scheduled tasks
- Recently modified scripts in user directories

### 🟢 Low (Green)
**Informational - Monitor for changes**
- Disabled user accounts
- Standard system processes
- Normal network activity

### 🔵 Info (Blue)
**Normal system activity**
- Standard Windows services
- Expected network connections
- Normal file modifications

## External Resources

The application provides links to authoritative security resources:

- **VirusTotal**: https://www.virustotal.com/ - File and URL scanning
- **Hybrid Analysis**: https://www.hybrid-analysis.com/ - Malware analysis
- **MITRE ATT&CK**: https://attack.mitre.org/ - Adversary tactics and techniques
- **Microsoft Security**: https://www.microsoft.com/en-us/security/ - Windows security guidance
- **CISA Alerts**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog - Vulnerability alerts
- **Have I Been Pwned**: https://haveibeenpwned.com/ - Credential breach checking
- **AbuseIPDB**: https://www.abuseipdb.com/ - IP address reputation

## Report Structure

All reports are saved to `Desktop\Cyber_Forensic_Report\` with the following structure:

```
Cyber_Forensic_Report/
├── SUMMARY/
│   ├── Executive_Summary.txt
│   ├── Threat_Assessment.txt
│   ├── Severity_Report.txt
│   └── Recommendations.txt
├── NETWORK_FORENSICS/
│   ├── Active_Connections.txt
│   ├── DNS_Cache.txt
│   ├── Routing_Table.txt
│   └── ARP_Cache.txt
├── PROCESS_ANALYSIS/
│   ├── Process_List.txt
│   ├── High_CPU_Processes.txt
│   ├── Loaded_DLLs.txt
│   └── Suspicious_Processes.txt
├── USER_AUDIT/
│   ├── Local_Users.txt
│   ├── Admin_Group_Members.txt
│   ├── Active_Sessions.txt
│   └── Privilege_Escalation.txt
├── PERSISTENCE/
│   ├── Registry_Run_Keys.txt
│   ├── Scheduled_Tasks.txt
│   ├── Services_Audit.txt
│   └── Startup_Items.txt
├── FILE_SYSTEM/
│   ├── Modified_System_Files.txt
│   ├── Temp_Executables.txt
│   ├── Suspicious_Files.txt
│   └── File_Hashes.txt
├── FIREWALL_HOSTS/
│   ├── Firewall_Rules.txt
│   ├── Hosts_File.txt
│   └── Network_Policies.txt
├── EVENT_LOGS/
│   ├── Failed_Logins.txt
│   ├── Successful_Logins.txt
│   ├── PowerShell_Events.txt
│   └── Security_Events.txt
├── REGISTRY/ (NEW)
│   ├── SAM.hive
│   ├── SYSTEM.hive
│   ├── SECURITY.hive
│   ├── SOFTWARE.hive
│   ├── NTUSER_*.hive
│   ├── DEFAULT.hive
│   ├── BCD.hive
│   └── Registry_Extraction.log
├── MEMORY/ (NEW)
│   ├── Process_Memory_Usage.txt
│   ├── Process_Details.txt
│   ├── Loaded_DLLs.txt
│   ├── Driver_List.txt
│   └── Memory_Extraction.log
├── ARTIFACTS/ (NEW)
│   ├── Prefetch/
│   ├── Amcache.hve
│   ├── SRUDB.dat
│   ├── ShimCache.txt
│   ├── BAM.txt
│   ├── Shellbags.txt
│   ├── JumpLists/
│   ├── RecentDocs.txt
│   └── Artifact_Collection.log
├── EVENTLOGS/ (NEW)
│   ├── Application.evtx
│   ├── System.evtx
│   ├── Security.evtx
│   ├── PowerShell.evtx
│   ├── TaskScheduler.evtx
│   ├── WindowsDefender.evtx
│   ├── BITS.evtx
│   ├── RDP.evtx
│   ├── WMI.evtx
│   └── EventLog_Export.log
├── TEMP_LOGS/ (NEW)
│   └── CMD_*.log (Temporary command logs for Telegram)
└── METADATA/
    ├── Scan_Timestamp.txt
    ├── System_Info.txt
    ├── Scan_Duration.txt
    └── Tool_Version.txt
```

## Keyboard Shortcuts

- **Ctrl+F**: Search within the current tab (when search box is focused)
- **Click column header**: Sort table by that column
- **Right-click**: Context menu (copy, export, mark false positive)

## Troubleshooting

### Application won't start
- Ensure you're running Python 3.7 or higher
- Run as Administrator: Right-click → "Run as administrator"
- Check that tkinter is installed (usually included with Python)

### Scan stops or hangs
- Click the "■ Stop Scan" button to halt the scan
- Check the live log window for error messages
- Some commands may take time to complete on large systems

### No results appearing
- Ensure the scan has completed (progress bar at 100%)
- Check the live log window for scan status
- Try clearing results and running the scan again

### Permission errors
- The application requires administrator privileges
- Some system areas may be protected even with admin rights
- Check Windows Event Viewer for detailed permission errors

## Security Considerations

- **No external network calls**: All data is collected and stored locally
- **No data transmission**: No information is sent to external servers
- **Opt-in cloud analysis**: VirusTotal and other external tools require manual action
- **Local storage only**: All reports are saved to your local Desktop
- **Admin privileges required**: Necessary for comprehensive system scanning

## Performance

- **Scan duration**: Typically 5-15 minutes depending on system size
- **Memory usage**: Approximately 100-200MB during scan
- **Disk usage**: Report folder size varies (typically 10-50MB)
- **CPU impact**: Moderate during scan, minimal when idle

## Future Enhancements

Planned features for future versions:
- Historical scan comparison
- Automated threat intelligence integration
- Real-time monitoring mode
- Scheduled scans
- Remote system scanning
- Advanced reporting templates
- Custom rule configuration
- Integration with SIEM systems

## License

This tool is provided as-is for educational and professional security analysis purposes.

## Support

For issues, questions, or contributions:
- Review the Help menu in the application
- Check the live log window for error details
- Ensure you have the latest version of the application

## Version History

### v8.0.0 (Current - Enterprise Edition)
- Deep forensic artifact collection (Registry hives, Memory, MFT, Prefetch, Amcache, SRUM, Shellbags, Jump Lists)
- Full Event Log export (Application, System, Security, PowerShell, TaskScheduler, Defender, BITS, RDP, WMI)
- Telegram bot integration with remote command execution
- Rolling log display with download capability
- AI-powered anomaly detection framework
- Real-time monitoring daemon
- Enhanced batch script with 12 forensic steps
- External API integration (AbuseIPDB, VirusTotal)
- Machine learning dependencies (scikit-learn, numpy, pandas)

### v5.0.0
- Complete GUI redesign with tkinter
- Real-time progress tracking
- Automatic threat detection and severity scoring
- Intelligent recommendations with URL references
- Organized folder structure for reports
- Interactive data display with tables and filtering
- Export to multiple formats (JSON, CSV, PDF)
- Color-coded severity indicators
- Detail panel with recommendations

### v4.0 (Original Batch Script)
- Command-line interface
- Basic security scanning
- Text-based report generation

## Credits

**Created by Hasan Ibrahim**

Converted from the original 2.bat cyber forensics script to a modern GUI application with enhanced features and usability.
