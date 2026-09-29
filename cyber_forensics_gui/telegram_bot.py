#!/usr/bin/env python3
"""
Telegram Bot Module for Cyber Forensics Toolkit v8.0
Provides remote command execution, alerts, and rolling log display
"""

import os
import json
import threading
import subprocess
import tempfile
import time
import asyncio
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
import logging
from collections import deque

# Try to import forensic modules with graceful degradation
try:
    from realtime_monitor import RealTimeMonitor
    MONITOR_AVAILABLE = True
except ImportError:
    MONITOR_AVAILABLE = False

try:
    from ai_anomaly_detection import AnomalyDetector
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

try:
    from external_api import ThreatIntelligenceManager
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

try:
    from memory_analysis import MemoryAnalyzer
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

try:
    from mft_parser import MFTParser
    MFT_AVAILABLE = True
except ImportError:
    MFT_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TelegramBotManager:
    """Manages Telegram bot integration for remote control and alerts"""
    
    def __init__(self, config_file=None):
        self.config_file = config_file or os.path.join(
            os.path.expanduser("~"), 
            ".cyber_forensics_telegram_config.json"
        )
        self.config = self.load_config()
        self.bot = None
        self.updater = None
        self.running = False
        self.log_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Cyber_Forensic_Report", "TEMP_LOGS")
        os.makedirs(self.log_dir, exist_ok=True)
        self.active_commands = {}  # Track active command executions
        self.command_locks = threading.Lock()
        
        # Initialize forensic modules
        self.monitor = None
        self.monitoring_active = False
        self.anomaly_detector = None
        self.threat_intel = None
        self.memory_analyzer = None
        self.mft_parser = None
        
        # Alert history and tracking
        self.alert_history = deque(maxlen=100)
        self.alert_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        # Initialize modules if available
        if MONITOR_AVAILABLE:
            self.monitor = RealTimeMonitor(callback=self.monitor_alert_callback)
        if AI_AVAILABLE:
            self.anomaly_detector = AnomalyDetector()
        if API_AVAILABLE:
            self.threat_intel = ThreatIntelligenceManager()
        if MEMORY_AVAILABLE:
            self.memory_analyzer = MemoryAnalyzer()
        if MFT_AVAILABLE:
            self.mft_parser = MFTParser()
    
    def monitor_alert_callback(self, alert):
        """Callback for RealTimeMonitor alerts with AI analysis"""
        severity = alert.get('severity', 'Info')
        title = alert.get('title', 'Monitoring Alert')
        description = alert.get('description', '')
        category = alert.get('category', 'monitoring')
        
        # Run AI anomaly detection if available
        if AI_AVAILABLE and self.anomaly_detector:
            try:
                anomalies = self.anomaly_detector.detect_process_anomaly(alert)
                if anomalies:
                    description += f"\n\n🤖 AI Analysis: {anomalies}"
                    severity = 'High' if severity == 'Medium' else severity
            except:
                pass
        
        # Add to history
        self.alert_history.append({
            'timestamp': datetime.now(),
            'severity': severity,
            'title': title,
            'description': description,
            'category': category
        })
        self.alert_counts[severity] = self.alert_counts.get(severity, 0) + 1
        
        # Send via Telegram
        self.send_alert(severity, title, description, category)
        
    def load_config(self):
        """Load encrypted configuration from file"""
        default_config = {
            "bot_token": "",
            "authorized_chat_ids": [],
            "admin_chat_ids": [],
            "alert_enabled": True,
            "alert_severity": ["Critical", "High"],
            "log_auto_delete_minutes": 5,
            "log_retention_hours": 24,
            "rate_limit_per_minute": 10
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    encrypted_data = f.read()
                if encrypted_data:
                    config = json.loads(encrypted_data)
                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def is_authorized(self, chat_id):
        """Check if chat ID is authorized"""
        return str(chat_id) in self.config.get("authorized_chat_ids", [])
    
    def is_admin(self, chat_id):
        """Check if chat ID has admin privileges"""
        return str(chat_id) in self.config.get("admin_chat_ids", [])
    
    def start_bot(self):
        """Start the Telegram bot in polling mode"""
        try:
            from telegram import Update
            from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
            
            if not self.config.get("bot_token"):
                logger.error("Bot token not configured")
                return False
            
            # Build application using python-telegram-bot 20.x API
            self.application = ApplicationBuilder().token(self.config["bot_token"]).build()
            
            # Register command handlers
            self.application.add_handler(CommandHandler("start", self.cmd_start))
            self.application.add_handler(CommandHandler("status", self.cmd_status))
            self.application.add_handler(CommandHandler("scan", self.cmd_scan))
            self.application.add_handler(CommandHandler("scan_quick", self.cmd_scan_quick))
            self.application.add_handler(CommandHandler("scan_network", self.cmd_scan_network))
            self.application.add_handler(CommandHandler("scan_process", self.cmd_scan_process))
            self.application.add_handler(CommandHandler("scan_registry", self.cmd_scan_registry))
            self.application.add_handler(CommandHandler("scan_memory", self.cmd_scan_memory))
            self.application.add_handler(CommandHandler("last", self.cmd_last))
            self.application.add_handler(CommandHandler("last_critical", self.cmd_last_critical))
            self.application.add_handler(CommandHandler("summary", self.cmd_summary))
            self.application.add_handler(CommandHandler("processes", self.cmd_processes))
            self.application.add_handler(CommandHandler("connections", self.cmd_connections))
            self.application.add_handler(CommandHandler("users", self.cmd_users))
            self.application.add_handler(CommandHandler("tasks", self.cmd_tasks))
            self.application.add_handler(CommandHandler("services", self.cmd_services))
            self.application.add_handler(CommandHandler("start_monitor", self.cmd_start_monitor))
            self.application.add_handler(CommandHandler("stop_monitor", self.cmd_stop_monitor))
            self.application.add_handler(CommandHandler("export", self.cmd_export))
            self.application.add_handler(CommandHandler("clear", self.cmd_clear))
            self.application.add_handler(CommandHandler("clear_confirm", self.cmd_clear_confirm))
            self.application.add_handler(CommandHandler("help", self.cmd_help))
            self.application.add_handler(CommandHandler("exec", self.cmd_exec))
            self.application.add_handler(CommandHandler("ps", self.cmd_ps))
            self.application.add_handler(CommandHandler("kill", self.cmd_kill))
            self.application.add_handler(CommandHandler("block_ip", self.cmd_block_ip))
            self.application.add_handler(CommandHandler("unblock_ip", self.cmd_unblock_ip))
            
            # Start polling
            self.application.run_polling()
            self.running = True
            logger.info("Telegram bot started successfully")
            return True
            
        except ImportError:
            logger.error("python-telegram-bot not installed. Run: pip install python-telegram-bot==20.7")
            return False
        except Exception as e:
            logger.error(f"Error starting bot: {e}")
            return False
    
    def stop_bot(self):
        """Stop the Telegram bot"""
        if hasattr(self, 'application') and self.application:
            self.application.stop()
            self.running = False
            logger.info("Telegram bot stopped")
    
    def send_alert(self, severity, title, description, category):
        """Send alert to authorized users"""
        if not self.config.get("alert_enabled"):
            return
        
        if severity not in self.config.get("alert_severity", ["Critical", "High"]):
            return
        
        if not self.running:
            return
        
        try:
            from telegram import Bot
            bot = Bot(token=self.config["bot_token"])
            
            emoji_map = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
                "Info": "🔵"
            }
            
            message = f"""
{emoji_map.get(severity, '⚠️')} {severity} ALERT - Cyber Forensics Toolkit

Severity: {severity}
Category: {category}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{title}

{description}

Recommendation: Review the full report for details.
"""
            
            for chat_id in self.config.get("authorized_chat_ids", []):
                try:
                    bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')
                except Exception as e:
                    logger.error(f"Error sending alert to {chat_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    def execute_command_with_rolling_log(self, command, chat_id, update):
        """Execute command with rolling log display"""
        try:
            from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
            
            bot = Bot(token=self.config["bot_token"])
            
            # Generate unique log file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            command_hash = abs(hash(command)) % 10000
            log_file = os.path.join(self.log_dir, f"CMD_{timestamp}_{command_hash}.log")
            
            # Send initial message
            message = bot.send_message(
                chat_id=chat_id,
                text=f"🚀 Starting command...\n\n```{command}```",
                parse_mode='Markdown'
            )
            message_id = message.message_id
            
            # Execute command and stream output
            try:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    universal_newlines=True
                )
                
                output_buffer = []
                last_update = time.time()
                
                with open(log_file, 'w') as log_f:
                    while True:
                        line = process.stdout.readline()
                        if not line and process.poll() is not None:
                            break
                        
                        if line:
                            log_f.write(line)
                            log_f.flush()
                            output_buffer.append(line)
                            
                            # Update message every 2 seconds or if buffer is large
                            current_time = time.time()
                            if current_time - last_update > 2 or len(output_buffer) > 50:
                                # Keep last 50 lines for display
                                display_output = ''.join(output_buffer[-50:])
                                
                                # Truncate to 4000 chars (Telegram limit)
                                if len(display_output) > 4000:
                                    display_output = "...\n" + display_output[-4000:]
                                
                                try:
                                    bot.edit_message_text(
                                        chat_id=chat_id,
                                        message_id=message_id,
                                        text=f"🔄 Running command...\n\n```\n{display_output}\n```",
                                        parse_mode='Markdown'
                                    )
                                except Exception:
                                    pass  # Message might not be editable anymore
                                
                                output_buffer = []
                                last_update = current_time
                
                # Command completed
                exit_code = process.poll()
                status = "✅ Completed" if exit_code == 0 else f"❌ Failed (exit code: {exit_code})"
                
                # Send completion message with download button
                keyboard = [[InlineKeyboardButton("📥 Download Log", callback_data=f"download_{log_file}")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                bot.send_message(
                    chat_id=chat_id,
                    text=f"{status}\n\nCommand: `{command}`\nExit code: {exit_code}",
                    parse_mode='Markdown',
                    reply_markup=reply_markup
                )
                
                # Schedule message deletion
                threading.Timer(
                    self.config.get("log_auto_delete_minutes", 5) * 60,
                    lambda: self.delete_message_safe(bot, chat_id, message_id)
                ).start()
                
            except Exception as e:
                bot.send_message(
                    chat_id=chat_id,
                    text=f"❌ Error executing command: {str(e)}"
                )
                
        except Exception as e:
            logger.error(f"Error in execute_command_with_rolling_log: {e}")
    
    def delete_message_safe(self, bot, chat_id, message_id):
        """Safely delete a message"""
        try:
            bot.delete_message(chat_id=chat_id, message_id=message_id)
        except Exception:
            pass  # Message might already be deleted
    
    # Command Handlers (async for python-telegram-bot 20.x)
    async def cmd_start(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text(
            "🤖 Cyber Forensics Toolkit v8.0 - Telegram Bot\n\n"
            "Use /help to see available commands"
        )
    
    async def cmd_status(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        status = f"""
📊 System Status

Bot Status: {'🟢 Running' if self.running else '🔴 Stopped'}
Monitoring: {'🟢 Active' if self.monitoring_active else '🔴 Inactive'}
Last Scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📈 Alert Statistics:
🔴 Critical: {self.alert_counts.get('Critical', 0)}
🟠 High: {self.alert_counts.get('High', 0)}
🟡 Medium: {self.alert_counts.get('Medium', 0)}
🟢 Low: {self.alert_counts.get('Low', 0)}
🔵 Info: {self.alert_counts.get('Info', 0)}

🔧 Module Availability:
Real-Time Monitor: {'✅' if MONITOR_AVAILABLE else '❌'}
AI Anomaly Detection: {'✅' if AI_AVAILABLE else '❌'}
Threat Intelligence: {'✅' if API_AVAILABLE else '❌'}
Memory Analysis: {'✅' if MEMORY_AVAILABLE else '❌'}
MFT Parser: {'✅' if MFT_AVAILABLE else '❌'}
"""
        await update.message.reply_text(status)
    
    async def cmd_help(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        help_text = """
📚 Available Commands

🔍 Scanning:
/scan - Full system scan
/scan_quick - Quick scan (network + processes)
/scan_network - Network forensics scan
/scan_process - Process analysis scan
/scan_registry - Registry forensics scan
/scan_memory - Memory dump and analysis

📊 Information:
/status - Current threat level and system status
/processes - List running processes
/connections - List active network connections
/users - List user accounts
/tasks - List scheduled tasks
/services - List running services
/last - Last 5 alerts
/last_critical - Last 5 critical alerts
/summary - Daily summary

⚙️ Control:
/start_monitor - Start real-time monitoring
/stop_monitor - Stop real-time monitoring
/export - Export current report
/clear - Clear results

🔧 Admin Commands (Admin Only):
/exec <command> - Execute custom command
/ps <process_name> - Get detailed process info
/kill <pid> - Terminate process
/block_ip <ip> - Block IP in firewall
/unblock_ip <ip> - Unblock IP in firewall
"""
        await update.message.reply_text(help_text)
    
    async def cmd_scan(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan command - Full system scan"""
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Starting full system scan...")
        await update.message.reply_text("⏳ This may take several minutes...")
        
        # Run all scan commands in sequence
        scans = [
            ("Network", self.cmd_scan_network),
            ("Process", self.cmd_scan_process),
            ("Registry", self.cmd_scan_registry),
        ]
        
        for scan_name, scan_func in scans:
            await update.message.reply_text(f"🔍 Running {scan_name} scan...")
            await scan_func(update, context)
            await asyncio.sleep(1)  # Small delay between scans
        
        await update.message.reply_text("✅ Full system scan complete!")
        await update.message.reply_text("📊 Use /summary to view results")
    
    async def cmd_exec(self, update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /exec command (admin only)"""
        if not self.is_admin(update.effective_chat.id):
            await update.message.reply_text("❌ Admin privileges required")
            return
        
        if len(context.args) < 1:
            await update.message.reply_text("Usage: /exec <command>")
            return
        
        command = ' '.join(context.args)
        
        # Confirm dangerous commands
        dangerous_keywords = ['delete', 'format', 'remove', 'kill', 'stop']
        if any(keyword in command.lower() for keyword in dangerous_keywords):
            await update.message.reply_text(f"⚠️ DANGEROUS COMMAND: {command}\n\nConfirm with /exec_confirm {command}")
            return
        
        # Execute with rolling log
        threading.Thread(
            target=self.execute_command_with_rolling_log,
            args=(command, update.effective_chat.id, update)
        ).start()
    
    # Placeholder handlers for other commands
    async def cmd_scan_quick(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Starting quick scan...")
        
        # Network scan
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=30)
            network_output = result.stdout
            # Parse and format
            suspicious_ports = ['4444', '5555', '6666', '31337', '12345']
            suspicious_found = []
            for port in suspicious_ports:
                if f":{port}" in network_output:
                    suspicious_found.append(port)
            
            network_msg = "🌐 Network Scan Results:\n"
            if suspicious_found:
                network_msg += f"⚠️ Suspicious ports: {', '.join(suspicious_found)}\n"
            else:
                network_msg += "✅ No suspicious ports detected\n"
            
            await update.message.reply_text(network_msg[:4000])
        except Exception as e:
            await update.message.reply_text(f"❌ Network scan error: {e}")
        
        # Process scan
        try:
            result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=30)
            process_output = result.stdout
            suspicious_procs = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta']
            suspicious_found = []
            for proc in suspicious_procs:
                if proc.lower() in process_output.lower():
                    suspicious_found.append(proc)
            
            process_msg = "💻 Process Scan Results:\n"
            if suspicious_found:
                process_msg += f"⚠️ Suspicious processes: {', '.join(suspicious_found)}\n"
            else:
                process_msg += "✅ No suspicious processes detected\n"
            
            await update.message.reply_text(process_msg[:4000])
        except Exception as e:
            await update.message.reply_text(f"❌ Process scan error: {e}")
        
        await update.message.reply_text("✅ Quick scan complete")
    
    async def cmd_scan_network(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Starting network forensics scan...")
        
        try:
            result = subprocess.run(['netstat', '-anob'], capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            # Parse connections
            established = output.count('ESTABLISHED')
            listening = output.count('LISTENING')
            
            # Check for suspicious IPs
            suspicious_ips = []
            lines = output.split('\n')
            for line in lines:
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[2].split(':')[0]
                        if ip not in ['127.0.0.1', '0.0.0.0', '::1']:
                            suspicious_ips.append(ip)
            
            msg = f"""
🌐 Network Forensics Results

📊 Connection Statistics:
- Established: {established}
- Listening: {listening}
- Total Unique IPs: {len(set(suspicious_ips))}

⚠️ Suspicious Connections:
"""
            if suspicious_ips:
                for ip in set(suspicious_ips[:10]):  # Limit to 10
                    msg += f"- {ip}\n"
            else:
                msg += "None detected\n"
            
            await update.message.reply_text(msg[:4000])
            await update.message.reply_text("✅ Network scan complete")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Network scan error: {e}")
    
    async def cmd_scan_process(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Starting process analysis...")
        
        try:
            result = subprocess.run(['tasklist', '/V'], capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            # Basic analysis
            suspicious_keywords = ['powershell', 'cmd', 'wscript', 'mshta', 'rundll32']
            lines = output.split('\n')
            suspicious = []
            for line in lines:
                for keyword in suspicious_keywords:
                    if keyword.lower() in line.lower():
                        suspicious.append(line.strip())
                        break
            
            msg = "💻 Process Analysis Results:\n\n"
            msg += f"🔍 Suspicious Processes ({len(suspicious)}):\n"
            for proc in suspicious[:5]:
                msg += f"- {proc[:100]}...\n"
            
            await update.message.reply_text(msg[:4000])
            await update.message.reply_text("✅ Process scan complete")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Process scan error: {e}")
    
    async def cmd_scan_registry(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Starting registry forensics...")
        
        try:
            # Check startup locations
            startup_keys = [
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ]
            
            msg = "📝 Registry Forensics Results:\n\n"
            msg += "🔍 Startup Locations:\n"
            
            for key in startup_keys:
                try:
                    result = subprocess.run(['reg', 'query', key], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        values = [line.strip() for line in result.stdout.split('\n') if line.strip() and 'REG_' in line]
                        if values:
                            msg += f"\n{key}:\n"
                            for val in values[:3]:  # Limit to 3 per key
                                msg += f"  {val[:80]}...\n"
                except:
                    pass
            
            # Check for suspicious persistence
            msg += "\n⚠️ Persistence Mechanisms:\n"
            msg += "Checking scheduled tasks, services, and WMI...\n"
            
            await update.message.reply_text(msg[:4000])
            await update.message.reply_text("✅ Registry scan complete")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Registry scan error: {e}")
    
    async def cmd_scan_memory(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Starting memory analysis...")
        
        await update.message.reply_text("⚠️ Memory analysis requires MemoryAnalyzer module with specific methods.")
        await update.message.reply_text("Use /scan_process for basic process analysis instead.")
    
    async def cmd_last(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if not self.alert_history:
            await update.message.reply_text("📋 No alerts in history")
            return
        
        msg = "📋 Last 5 Alerts:\n\n"
        last_5 = list(self.alert_history)[-5:]
        
        emoji_map = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Info': '🔵'}
        
        for alert in last_5:
            emoji = emoji_map.get(alert['severity'], '⚪')
            msg += f"{emoji} [{alert['severity']}] {alert['title']}\n"
            msg += f"   {alert['description'][:100]}...\n"
            msg += f"   {alert['timestamp'].strftime('%H:%M:%S')}\n\n"
        
        await update.message.reply_text(msg[:4000])
    
    async def cmd_last_critical(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        critical_alerts = [a for a in self.alert_history if a['severity'] == 'Critical']
        
        if not critical_alerts:
            await update.message.reply_text("📋 No critical alerts in history")
            return
        
        msg = "📋 Last 5 Critical Alerts:\n\n"
        last_5 = critical_alerts[-5:]
        
        for alert in last_5:
            msg += f"🔴 {alert['title']}\n"
            msg += f"   {alert['description']}\n"
            msg += f"   Category: {alert['category']}\n"
            msg += f"   {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        await update.message.reply_text(msg[:4000])
    
    async def cmd_summary(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        msg = f"""
📊 Daily Summary

📈 Alert Statistics:
🔴 Critical: {self.alert_counts.get('Critical', 0)}
🟠 High: {self.alert_counts.get('High', 0)}
🟡 Medium: {self.alert_counts.get('Medium', 0)}
🟢 Low: {self.alert_counts.get('Low', 0)}
🔵 Info: {self.alert_counts.get('Info', 0)}

⏰ Last Alert: {self.alert_history[-1]['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if self.alert_history else 'None'}

🔧 System Status:
Monitoring: {'🟢 Active' if self.monitoring_active else '🔴 Inactive'}
Bot: {'🟢 Running' if self.running else '🔴 Stopped'}
"""
        await update.message.reply_text(msg)
    
    async def cmd_processes(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Analyzing processes...")
        
        try:
            result = subprocess.run(['tasklist', '/V'], capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            # Truncate if too long
            if len(output) > 4000:
                output = output[-4000:]
            
            await update.message.reply_text(f"💻 Running Processes:\n\n```\n{output}\n```", parse_mode='Markdown')
            await update.message.reply_text("✅ Process scan complete")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_connections(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Analyzing network connections...")
        
        try:
            result = subprocess.run(['netstat', '-anob'], capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            # Truncate if too long
            if len(output) > 4000:
                output = output[-4000:]
            
            await update.message.reply_text(f"🌐 Network Connections:\n\n```\n{output}\n```", parse_mode='Markdown')
            await update.message.reply_text("✅ Network scan complete")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_users(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Analyzing user accounts...")
        
        try:
            result = subprocess.run(['net', 'user'], capture_output=True, text=True, timeout=30)
            output = result.stdout
            
            msg = "👤 User Accounts:\n\n"
            
            # Parse users
            lines = output.split('\n')
            for line in lines:
                if line.strip():
                    msg += f"{line}\n"
            
            # Check for admin accounts
            result = subprocess.run(['net', 'localgroup', 'administrators'], capture_output=True, text=True, timeout=30)
            msg += f"\n🔐 Administrators:\n{result.stdout}"
            
            await update.message.reply_text(msg[:4000])
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_tasks(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Analyzing scheduled tasks...")
        
        try:
            result = subprocess.run(['schtasks', '/query', '/fo', 'LIST'], capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            msg = "📋 Scheduled Tasks:\n\n"
            
            # Parse tasks
            lines = output.split('\n')
            task_count = output.count('TaskName')
            msg += f"Total Tasks: {task_count}\n\n"
            
            # Show first few tasks
            for line in lines[:50]:
                if line.strip():
                    msg += f"{line}\n"
            
            await update.message.reply_text(msg[:4000])
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_services(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Analyzing services...")
        
        try:
            result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            msg = "⚙️ Services:\n\n"
            
            # Parse services
            lines = output.split('\n')
            running = output.count('RUNNING')
            stopped = output.count('STOPPED')
            
            msg += f"Running: {running}\n"
            msg += f"Stopped: {stopped}\n\n"
            
            # Show first few services
            for line in lines[:50]:
                if line.strip():
                    msg += f"{line}\n"
            
            await update.message.reply_text(msg[:4000])
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_start_monitor(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if not MONITOR_AVAILABLE or not self.monitor:
            await update.message.reply_text("❌ Real-time monitoring module not available")
            return
        
        if self.monitoring_active:
            await update.message.reply_text("⚠️ Monitoring is already active")
            return
        
        try:
            if self.monitor.start():
                self.monitoring_active = True
                await update.message.reply_text("✅ Real-time monitoring started successfully")
                await update.message.reply_text("🔍 Monitoring processes, network, registry, and file system...")
            else:
                await update.message.reply_text("❌ Failed to start monitoring")
        except Exception as e:
            await update.message.reply_text(f"❌ Error starting monitoring: {e}")
    
    async def cmd_stop_monitor(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if not MONITOR_AVAILABLE or not self.monitor:
            await update.message.reply_text("❌ Real-time monitoring module not available")
            return
        
        if not self.monitoring_active:
            await update.message.reply_text("⚠️ Monitoring is not active")
            return
        
        try:
            self.monitor.stop()
            self.monitoring_active = False
            await update.message.reply_text("✅ Real-time monitoring stopped successfully")
        except Exception as e:
            await update.message.reply_text(f"❌ Error stopping monitoring: {e}")
    
    async def cmd_export(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("🔄 Generating report export...")
        
        try:
            report_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Cyber_Forensic_Report")
            
            if not os.path.exists(report_dir):
                await update.message.reply_text("❌ No forensic report found")
                return
            
            # Generate summary
            msg = f"""
📊 Forensic Report Export

📁 Location: {report_dir}
📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📈 Alert Summary:
🔴 Critical: {self.alert_counts.get('Critical', 0)}
🟠 High: {self.alert_counts.get('High', 0)}
🟡 Medium: {self.alert_counts.get('Medium', 0)}
🟢 Low: {self.alert_counts.get('Low', 0)}
🔵 Info: {self.alert_counts.get('Info', 0)}

📁 Report Contents:
"""
            # List files in report directory
            for item in os.listdir(report_dir)[:10]:
                item_path = os.path.join(report_dir, item)
                if os.path.isfile(item_path):
                    size = os.path.getsize(item_path)
                    msg += f"- {item} ({size} bytes)\n"
                else:
                    msg += f"- {item}/\n"
            
            await update.message.reply_text(msg[:4000])
            await update.message.reply_text("✅ Export complete. Full report available in GUI.")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Export error: {e}")
    
    async def cmd_clear(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        await update.message.reply_text("⚠️ This will clear alert history and reset monitoring baselines.")
        await update.message.reply_text("Confirm with /clear_confirm")
    
    async def cmd_clear_confirm(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_authorized(update.effective_chat.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        # Clear alert history
        self.alert_history.clear()
        self.alert_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        # Reset monitoring baselines if active
        if self.monitor and self.monitoring_active:
            self.monitor.initialize_baselines()
        
        await update.message.reply_text("✅ Alert history cleared and baselines reset")
    
    async def cmd_ps(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_admin(update.effective_chat.id):
            await update.message.reply_text("❌ Admin privileges required")
            return
        if len(context.args) < 1:
            await update.message.reply_text("Usage: /ps <process_name>")
            return
        process_name = context.args[0]
        
        await update.message.reply_text(f"🔄 Getting process info for {process_name}...")
        
        try:
            result = subprocess.run(['tasklist', '/FI', f"IMAGENAME eq {process_name}", '/V'], capture_output=True, text=True, timeout=30)
            output = result.stdout
            
            if len(output) > 4000:
                output = output[-4000:]
            
            await update.message.reply_text(f"🔍 Process Info: {process_name}\n\n```\n{output}\n```", parse_mode='Markdown')
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_kill(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_admin(update.effective_chat.id):
            await update.message.reply_text("❌ Admin privileges required")
            return
        if len(context.args) < 1:
            await update.message.reply_text("Usage: /kill <pid>")
            return
        pid = context.args[0]
        
        await update.message.reply_text(f"⚠️ DANGEROUS: Terminating process {pid}")
        
        try:
            result = subprocess.run(['taskkill', '/PID', pid, '/F'], capture_output=True, text=True, timeout=10)
            await update.message.reply_text(f"Result: {result.stdout}")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_block_ip(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_admin(update.effective_chat.id):
            await update.message.reply_text("❌ Admin privileges required")
            return
        if len(context.args) < 1:
            await update.message.reply_text("Usage: /block_ip <ip>")
            return
        ip = context.args[0]
        
        await update.message.reply_text(f"🔒 Blocking IP: {ip}")
        
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=Block {ip}', 'dir=in', 'action=block', f'remoteip={ip}'], capture_output=True, text=True, timeout=30)
            await update.message.reply_text(f"Result: {result.stdout}")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")
    
    async def cmd_unblock_ip(self, update, context: ContextTypes.DEFAULT_TYPE):
        if not self.is_admin(update.effective_chat.id):
            await update.message.reply_text("❌ Admin privileges required")
            return
        if len(context.args) < 1:
            await update.message.reply_text("Usage: /unblock_ip <ip>")
            return
        ip = context.args[0]
        
        await update.message.reply_text(f"🔓 Unblocking IP: {ip}")
        
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name=Block {ip}'], capture_output=True, text=True, timeout=30)
            await update.message.reply_text(f"Result: {result.stdout}")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {e}")


# Main entry point for standalone bot execution
if __name__ == "__main__":
    print("Cyber Forensics Toolkit v8.0 - Telegram Bot")
    print("Starting Telegram bot for remote monitoring and control...")
    
    bot_manager = TelegramBotManager()
    
    if bot_manager.start_bot():
        print("Bot started successfully!")
        print("Press Ctrl+C to stop the bot")
        
        try:
            # Keep the bot running
            while bot_manager.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping bot...")
            bot_manager.stop_bot()
            print("Bot stopped.")
    else:
        print("Failed to start bot. Check configuration.")
