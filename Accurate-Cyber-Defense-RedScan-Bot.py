#!/usr/bin/env python3
"""
Accurate Cyber Defense  - IP Threat Analysis System
A comprehensive tool for monitoring cybersecurity threats via IP addresses
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import platform
import sqlite3
from datetime import datetime
from pathlib import Path
import requests
import ping3
from scapy.all import *
import dpkt
from collections import deque
import readline
import logging
from typing import List, Dict, Any, Optional, Tuple
import ipaddress
import re

# ==============================
# CONFIGURATION AND SETUP
# ==============================
class Config:
    """Configuration management for the tool"""
    def __init__(self):
        self.home_dir = Path.home() / ".accurate_cyber_defense"
        self.home_dir.mkdir(exist_ok=True)
        
        self.config_file = self.home_dir / "config.json"
        self.history_file = self.home_dir / "command_history.txt"
        self.database_file = self.home_dir / "monitoring.db"
        self.log_file = self.home_dir / "activity.log"
        
        # Default configuration
        self.default_config = {
            "telegram": {
                "chat_id": "",
                "token": ""
            },
            "monitoring": {
                "ips": [],
                "ipv6s": [],
                "check_interval": 300  # 5 minutes
            },
            "theme": {
                "primary": "#00FF00",
                "secondary": "#00CC00",
                "text": "#FFFFFF",
                "background": "#001100"
            }
        }
        
        self.config = self.load_config()
        self.setup_logging()
        self.init_database()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print("Config file corrupted, creating new one")
        
        # Create default config
        with open(self.config_file, 'w') as f:
            json.dump(self.default_config, f, indent=4)
        return self.default_config.copy()
    
    def save_config(self) -> None:
        """Save current configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def setup_logging(self) -> None:
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("CyberMonitor")
    
    def init_database(self) -> None:
        """Initialize SQLite database for monitoring data"""
        conn = sqlite3.connect(self.database_file)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                type TEXT,
                added_date TEXT,
                last_checked TEXT,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT,
                timestamp TEXT,
                success BOOLEAN
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_type TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                timestamp TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

# ==============================
# NETWORK UTILITIES
# ==============================
class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def ping(host: str, ipv6: bool = False) -> Tuple[bool, float]:
        """Ping a host and return success status and response time"""
        try:
            # Use appropriate ping command based on platform
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", "-w", "2000"]
            
            if ipv6:
                command = ["ping6", param, "1", "-w", "2000"]
            
            response = subprocess.run(
                command + [host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            
            success = response.returncode == 0
            # Extract response time from output if available
            response_time = 0
            if success:
                output = response.stdout.decode()
                time_match = re.search(r"time=([\d.]+)\s*ms", output)
                if time_match:
                    response_time = float(time_match.group(1))
            
            return success, response_time
        except (subprocess.TimeoutExpired, Exception):
            return False, 0
    
    @staticmethod
    def traceroute(host: str, protocol: str = "udp") -> List[Dict[str, Any]]:
        """Perform traceroute to a host using specified protocol"""
        hops = []
        try:
            # Determine OS and set appropriate command
            if platform.system().lower() == "windows":
                command = ["tracert", "-h", "30", host]
            else:
                if protocol.lower() == "tcp":
                    command = ["tcptraceroute", "-m", "30", host]
                elif protocol.lower() == "udp":
                    command = ["traceroute", "-m", "30", host]
                else:
                    command = ["traceroute", "-m", "30", host]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )
            
            output = result.stdout.decode()
            lines = output.split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse traceroute output (simplified)
                if "*" in line:
                    # Timeout or no response
                    hops.append({"hop": len(hops) + 1, "ip": "*", "time": "*"})
                else:
                    # Extract IP and time
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)', line)
                    time_match = re.search(r'(\d+\.\d+\s*ms)', line)
                    
                    if ip_match:
                        hop_data = {
                            "hop": len(hops) + 1,
                            "ip": ip_match.group(1),
                            "time": time_match.group(1) if time_match else "*"
                        }
                        hops.append(hop_data)
            
            return hops
        except (subprocess.TimeoutExpired, Exception) as e:
            return [{"error": f"Traceroute failed: {str(e)}"}]
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if the given string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """Check if the given string is a valid IPv6 address"""
        try:
            addr = ipaddress.ip_address(ip)
            return isinstance(addr, ipaddress.IPv6Address)
        except ValueError:
            return False

# ==============================
# TELEGRAM INTEGRATION
# ==============================
class TelegramBot:
    """Telegram bot for remote control and notifications"""
    
    def __init__(self, config: Config):
        self.config = config
        self.token = config.config['telegram']['token']
        self.chat_id = config.config['telegram']['chat_id']
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.last_update_id = 0
        self.running = False
    
    def send_message(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send a message to the configured Telegram chat"""
        if not self.token or not self.chat_id:
            self.config.logger.warning("Telegram not configured properly")
            return False
        
        try:
            url = f"{self.base_url}/sendMessage"
            data = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": parse_mode
            }
            
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.config.logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    def get_updates(self) -> List[Dict[str, Any]]:
        """Get new updates from Telegram"""
        if not self.token:
            return []
        
        try:
            url = f"{self.base_url}/getUpdates"
            params = {"timeout": 30, "offset": self.last_update_id + 1}
            
            response = requests.get(url, params=params, timeout=35)
            if response.status_code != 200:
                return []
            
            data = response.json()
            if not data.get("ok"):
                return []
            
            updates = data.get("result", [])
            if updates:
                self.last_update_id = updates[-1]["update_id"]
            
            return updates
        except Exception as e:
            self.config.logger.error(f"Failed to get Telegram updates: {e}")
            return []
    
    def process_command(self, command: str, args: List[str] = None) -> str:
        """Process a command received via Telegram"""
        if not args:
            args = []
        
        # Map Telegram commands to internal functions
        command_map = {
            "/help": self.cmd_help,
            "/ping_ip": self.cmd_ping_ip,
            "/ping_ipv6": self.cmd_ping_ipv6,
            "/add_ip": self.cmd_add_ip,
            "/add_ipv6": self.cmd_add_ipv6,
            "/clear": self.cmd_clear,
            "/history": self.cmd_history,
            "/udptraceroute": self.cmd_udptraceroute,
            "/traceroute_ip": self.cmd_traceroute_ip,
            "/traceroute_ipv6": self.cmd_traceroute_ipv6,
            "/tcptraceroute": self.cmd_tcptraceroute,
            "/config": self.cmd_config,
            "/status": self.cmd_status,
            "/view": self.cmd_view
        }
        
        if command in command_map:
            return command_map[command](args)
        else:
            return f"Unknown command: {command}. Use /help for available commands."
    
    def cmd_help(self, args: List[str]) -> str:
        """Return help text"""
        help_text = """
<b>Accurate Cyber Defense Tool - Available Commands:</b>

<b>Basic Commands:</b>
/help - Show this help message
/status - Show monitoring status
/view - View monitored IPs

<b>IP Management:</b>
/add_ip [IP] - Add IPv4 address to monitor
/add_ipv6 [IP] - Add IPv6 address to monitor

<b>Network Diagnostics:</b>
/ping_ip [IP] - Ping an IPv4 address
/ping_ipv6 [IP] - Ping an IPv6 address
/traceroute_ip [IP] - Traceroute to IPv4 (UDP)
/traceroute_ipv6 [IP] - Traceroute to IPv6 (UDP)
/tcptraceroute [IP] - Traceroute using TCP
/udptraceroute [IP] - Traceroute using UDP

<b>Configuration:</b>
/config telegram_chat_id [ID] - Set Telegram chat ID
/config telegram_token [TOKEN] - Set Telegram bot token

<b>History:</b>
/history - Show command history
/clear - Clear command history
"""
        return help_text
    
    def cmd_ping_ip(self, args: List[str]) -> str:
        """Ping an IPv4 address"""
        if len(args) < 1:
            return "Usage: /ping_ip [IP_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ip(ip):
            return f"Invalid IP address: {ip}"
        
        success, response_time = NetworkUtils.ping(ip)
        if success:
            return f"Ping to {ip} successful. Response time: {response_time:.2f} ms"
        else:
            return f"Ping to {ip} failed"
    
    def cmd_ping_ipv6(self, args: List[str]) -> str:
        """Ping an IPv6 address"""
        if len(args) < 1:
            return "Usage: /ping_ipv6 [IPV6_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ipv6(ip):
            return f"Invalid IPv6 address: {ip}"
        
        success, response_time = NetworkUtils.ping(ip, ipv6=True)
        if success:
            return f"Ping to {ip} successful. Response time: {response_time:.2f} ms"
        else:
            return f"Ping to {ip} failed"
    
    def cmd_add_ip(self, args: List[str]) -> str:
        """Add an IPv4 address to monitor"""
        if len(args) < 1:
            return "Usage: /add_ip [IP_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ip(ip):
            return f"Invalid IP address: {ip}"
        
        # Add to config
        if ip not in self.config.config['monitoring']['ips']:
            self.config.config['monitoring']['ips'].append(ip)
            self.config.save_config()
            
            # Add to database
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO monitored_ips (ip, type, added_date, last_checked, status) VALUES (?, ?, ?, ?, ?)",
                (ip, "IPv4", datetime.now().isoformat(), datetime.now().isoformat(), "Added")
            )
            conn.commit()
            conn.close()
            
            return f"Added IPv4 address {ip} to monitoring"
        else:
            return f"IPv4 address {ip} is already being monitored"
    
    def cmd_add_ipv6(self, args: List[str]) -> str:
        """Add an IPv6 address to monitor"""
        if len(args) < 1:
            return "Usage: /add_ipv6 [IPV6_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ipv6(ip):
            return f"Invalid IPv6 address: {ip}"
        
        # Add to config
        if ip not in self.config.config['monitoring']['ipv6s']:
            self.config.config['monitoring']['ipv6s'].append(ip)
            self.config.save_config()
            
            # Add to database
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO monitored_ips (ip, type, added_date, last_checked, status) VALUES (?, ?, ?, ?, ?)",
                (ip, "IPv6", datetime.now().isoformat(), datetime.now().isoformat(), "Added")
            )
            conn.commit()
            conn.close()
            
            return f"Added IPv6 address {ip} to monitoring"
        else:
            return f"IPv6 address {ip} is already being monitored"
    
    def cmd_clear(self, args: List[str]) -> str:
        """Clear command history"""
        try:
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM command_history")
            conn.commit()
            conn.close()
            return "Command history cleared"
        except Exception as e:
            return f"Error clearing history: {str(e)}"
    
    def cmd_history(self, args: List[str]) -> str:
        """Show command history"""
        try:
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            cursor.execute("SELECT command, timestamp, success FROM command_history ORDER BY id DESC LIMIT 10")
            history = cursor.fetchall()
            conn.close()
            
            if not history:
                return "No command history found"
            
            result = "Last 10 commands:\n"
            for cmd, timestamp, success in history:
                status = "✓" if success else "✗"
                result += f"{timestamp}: {status} {cmd}\n"
            
            return result
        except Exception as e:
            return f"Error retrieving history: {str(e)}"
    
    def cmd_udptraceroute(self, args: List[str]) -> str:
        """Perform UDP traceroute"""
        if len(args) < 1:
            return "Usage: /udptraceroute [IP_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ip(ip):
            return f"Invalid IP address: {ip}"
        
        result = NetworkUtils.traceroute(ip, "udp")
        if result and "error" in result[0]:
            return f"Traceroute failed: {result[0]['error']}"
        
        # Format result
        response = f"UDP Traceroute to {ip}:\n"
        for hop in result:
            if "hop" in hop:
                response += f"{hop['hop']}: {hop.get('ip', '*')} {hop.get('time', '*')}\n"
        
        return response
    
    def cmd_traceroute_ip(self, args: List[str]) -> str:
        """Traceroute to IPv4 address"""
        return self.cmd_udptraceroute(args)
    
    def cmd_traceroute_ipv6(self, args: List[str]) -> str:
        """Traceroute to IPv6 address"""
        if len(args) < 1:
            return "Usage: /traceroute_ipv6 [IPV6_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ipv6(ip):
            return f"Invalid IPv6 address: {ip}"
        
        # Note: IPv6 traceroute implementation would go here
        # This is a simplified version
        return f"IPv6 traceroute to {ip} would be performed here"
    
    def cmd_tcptraceroute(self, args: List[str]) -> str:
        """Perform TCP traceroute"""
        if len(args) < 1:
            return "Usage: /tcptraceroute [IP_ADDRESS]"
        
        ip = args[0]
        if not NetworkUtils.is_valid_ip(ip):
            return f"Invalid IP address: {ip}"
        
        result = NetworkUtils.traceroute(ip, "tcp")
        if result and "error" in result[0]:
            return f"Traceroute failed: {result[0]['error']}"
        
        # Format result
        response = f"TCP Traceroute to {ip}:\n"
        for hop in result:
            if "hop" in hop:
                response += f"{hop['hop']}: {hop.get('ip', '*')} {hop.get('time', '*')}\n"
        
        return response
    
    def cmd_config(self, args: List[str]) -> str:
        """Configure Telegram settings"""
        if len(args) < 2:
            return "Usage: /config [telegram_chat_id|telegram_token] [VALUE]"
        
        config_type = args[0]
        value = args[1]
        
        if config_type == "telegram_chat_id":
            self.config.config['telegram']['chat_id'] = value
            self.chat_id = value
            self.config.save_config()
            return "Telegram chat ID updated"
        elif config_type == "telegram_token":
            self.config.config['telegram']['token'] = value
            self.token = value
            self.base_url = f"https://api.telegram.org/bot{self.token}"
            self.config.save_config()
            return "Telegram token updated"
        else:
            return f"Unknown configuration option: {config_type}"
    
    def cmd_status(self, args: List[str]) -> str:
        """Show monitoring status"""
        ip_count = len(self.config.config['monitoring']['ips'])
        ipv6_count = len(self.config.config['monitoring']['ipv6s'])
        
        # Get last check time from database
        conn = sqlite3.connect(self.config.database_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM monitored_ips WHERE status != 'Removed'")
        monitored_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT MAX(last_checked) FROM monitored_ips")
        last_checked = cursor.fetchone()[0] or "Never"
        conn.close()
        
        return f"""
<b>Monitoring Status:</b>
Monitored IPs: {monitored_count} ({ip_count} IPv4, {ipv6_count} IPv6)
Last checked: {last_checked}
Telegram configured: {'Yes' if self.token and self.chat_id else 'No'}
        """
    
    def cmd_view(self, args: List[str]) -> str:
        """View monitored IPs"""
        try:
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            cursor.execute("SELECT ip, type, added_date, last_checked, status FROM monitored_ips WHERE status != 'Removed'")
            ips = cursor.fetchall()
            conn.close()
            
            if not ips:
                return "No IP addresses being monitored"
            
            result = "<b>Monitored IP Addresses:</b>\n"
            for ip, ip_type, added_date, last_checked, status in ips:
                result += f"{ip_type}: {ip} (Added: {added_date[:10]}, Status: {status})\n"
            
            return result
        except Exception as e:
            return f"Error retrieving monitored IPs: {str(e)}"
    
    def start_bot(self) -> None:
        """Start the Telegram bot to listen for commands"""
        if not self.token:
            self.config.logger.warning("Telegram token not configured. Bot not started.")
            return
        
        self.running = True
        self.config.logger.info("Starting Telegram bot...")
        
        while self.running:
            try:
                updates = self.get_updates()
                for update in updates:
                    if "message" in update and "text" in update["message"]:
                        message = update["message"]
                        chat_id = message["chat"]["id"]
                        text = message["text"]
                        
                        # Only process if it's from the configured chat
                        if str(chat_id) == self.chat_id:
                            # Parse command
                            parts = text.split()
                            command = parts[0]
                            args = parts[1:] if len(parts) > 1 else []
                            
                            # Process command
                            response = self.process_command(command, args)
                            
                            # Send response
                            self.send_message(response)
                            
                            # Log command
                            self.config.logger.info(f"Telegram command: {text}")
            
            except Exception as e:
                self.config.logger.error(f"Error in Telegram bot: {e}")
            
            time.sleep(1)
    
    def stop_bot(self) -> None:
        """Stop the Telegram bot"""
        self.running = False

# ==============================
# SECURITY MONITORING
# ==============================
class SecurityMonitor:
    """Monitor IP addresses for security threats"""
    
    def __init__(self, config: Config, telegram_bot: TelegramBot):
        self.config = config
        self.telegram_bot = telegram_bot
        self.monitoring = False
        self.check_interval = config.config['monitoring']['check_interval']
    
    def start_monitoring(self) -> None:
        """Start monitoring IP addresses"""
        self.monitoring = True
        self.config.logger.info("Starting security monitoring")
        
        while self.monitoring:
            try:
                self.check_all_ips()
                time.sleep(self.check_interval)
            except Exception as e:
                self.config.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    def stop_monitoring(self) -> None:
        """Stop monitoring IP addresses"""
        self.monitoring = False
    
    def check_all_ips(self) -> None:
        """Check all monitored IP addresses"""
        ips = self.config.config['monitoring']['ips']
        ipv6s = self.config.config['monitoring']['ipv6s']
        
        self.config.logger.info(f"Checking {len(ips)} IPv4 and {len(ipv6s)} IPv6 addresses")
        
        # Check IPv4 addresses
        for ip in ips:
            status = self.check_ip(ip, False)
            self.update_ip_status(ip, status)
        
        # Check IPv6 addresses
        for ip in ipv6s:
            status = self.check_ip(ip, True)
            self.update_ip_status(ip, status)
    
    def check_ip(self, ip: str, is_ipv6: bool) -> Dict[str, Any]:
        """Check a single IP address for security issues"""
        result = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "reachable": False,
            "response_time": 0,
            "ports_open": [],
            "threat_level": "low",
            "details": ""
        }
        
        # Ping the IP
        reachable, response_time = NetworkUtils.ping(ip, is_ipv6)
        result["reachable"] = reachable
        result["response_time"] = response_time
        
        if not reachable:
            result["threat_level"] = "unknown"
            result["details"] = "Host is not reachable"
            return result
        
        # Simple port scan (common ports)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        open_ports = []
        for port in common_ports:
            if self.check_port(ip, port):
                open_ports.append(port)
        
        result["ports_open"] = open_ports
        
        # Basic threat assessment
        if any(port in [22, 23, 3389] for port in open_ports):
            result["threat_level"] = "medium"
            result["details"] = "Remote access ports open"
        
        if any(port in [135, 139, 445] for port in open_ports):
            result["threat_level"] = "high"
            result["details"] = "Windows sharing ports open"
        
        return result
    
    def check_port(self, ip: str, port: int) -> bool:
        """Check if a port is open on an IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def update_ip_status(self, ip: str, status: Dict[str, Any]) -> None:
        """Update the status of an IP in the database"""
        try:
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            
            # Update the IP status
            cursor.execute(
                "UPDATE monitored_ips SET last_checked = ?, status = ? WHERE ip = ?",
                (status["timestamp"], status["threat_level"], ip)
            )
            
            # Log the security event if there's a threat
            if status["threat_level"] in ["medium", "high"]:
                cursor.execute(
                    "INSERT INTO security_logs (log_type, source_ip, destination_ip, timestamp, details) VALUES (?, ?, ?, ?, ?)",
                    ("threat_detected", ip, "N/A", status["timestamp"], status["details"])
                )
                
                # Send alert via Telegram
                if self.telegram_bot.token and self.telegram_bot.chat_id:
                    message = f"🚨 <b>Security Alert</b> 🚨\nIP: {ip}\nThreat Level: {status['threat_level']}\nDetails: {status['details']}"
                    self.telegram_bot.send_message(message)
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.config.logger.error(f"Error updating IP status: {e}")

# ==============================
# COMMAND LINE INTERFACE
# ==============================
class CLI:
    """Command Line Interface for the tool"""
    
    def __init__(self, config: Config, telegram_bot: TelegramBot, security_monitor: SecurityMonitor):
        self.config = config
        self.telegram_bot = telegram_bot
        self.security_monitor = security_monitor
        self.running = False
        self.command_history = deque(maxlen=100)
        
        # Set up readline for command history
        readline.set_history_length(100)
        if self.config.history_file.exists():
            readline.read_history_file(self.config.history_file)
    
    def print_banner(self) -> None:
        """Print the tool banner"""
        banner = f"""
        {Fore.GREEN}╔══════════════════════════════════════════════════════
        ║                                                                                
        ║            Accurate Cyber Defense                                              
        ║                                                                                
        ║            Community:https://github.com/Accurate-Cyber-Defense 
                            
        ║                                                                                 
        ╚══════════════════════════════════════════════════════════════╝
        {Style.RESET_ALL}
        """
        print(banner)
    
    def print_help(self) -> None:
        """Print help information"""
        help_text = f"""
        {Fore.GREEN}Available Commands:{Style.RESET_ALL}
        
        {Fore.GREEN}Basic Commands:{Style.RESET_ALL}
          help                 Show this help message
          exit, quit           Exit the program
          clear                Clear the screen
        
        {Fore.GREEN}IP Management:{Style.RESET_ALL}
          add ip <IP>          Add IPv4 address to monitor
          add ipv6 <IP>        Add IPv6 address to monitor
          remove ip <IP>       Remove IP from monitoring
          view                 View monitored IPs
        
        {Fore.GREEN}Network Diagnostics:{Style.RESET_ALL}
          ping ip <IP>         Ping an IPv4 address
          ping ipv6 <IP>       Ping an IPv6 address
          traceroute ip <IP>   Traceroute to IPv4 (UDP)
          traceroute ipv6 <IP> Traceroute to IPv6 (UDP)
          tcptraceroute <IP>   Traceroute using TCP
          udptraceroute <IP>   Traceroute using UDP
        
        {Fore.GREEN}Telegram Integration:{Style.RESET_ALL}
          config telegram chat_id <ID>     Set Telegram chat ID
          config telegram token <TOKEN>    Set Telegram bot token
          telegram test                    Send test Telegram message
          telegram status                  Check Telegram connection
        
        {Fore.GREEN}Monitoring:{Style.RESET_ALL}
          monitor start        Start monitoring IPs
          monitor stop         Stop monitoring
          monitor status       Show monitoring status
          logs view            View security logs
        
        {Fore.GREEN}History:{Style.RESET_ALL}
          history              Show command history
          history clear        Clear command history
        """
        print(help_text)
    
    def save_command_history(self) -> None:
        """Save command history to file"""
        try:
            readline.write_history_file(self.config.history_file)
        except Exception as e:
            self.config.logger.error(f"Error saving command history: {e}")
    
    def log_command(self, command: str, success: bool = True) -> None:
        """Log a command to the database"""
        try:
            conn = sqlite3.connect(self.config.database_file)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO command_history (command, timestamp, success) VALUES (?, ?, ?)",
                (command, datetime.now().isoformat(), success)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            self.config.logger.error(f"Error logging command: {e}")
    
    def execute_command(self, command: str) -> bool:
        """Execute a command"""
        parts = command.split()
        if not parts:
            return True
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd in ["exit", "quit"]:
                self.running = False
                return True
            
            elif cmd == "help":
                self.print_help()
            
            elif cmd == "clear":
                os.system("clear" if os.name != "nt" else "cls")
            
            elif cmd == "add":
                if len(args) < 2:
                    print("Usage: add [ip|ipv6] [ADDRESS]")
                else:
                    if args[0] == "ip":
                        result = self.telegram_bot.cmd_add_ip([args[1]])
                        print(result)
                    elif args[0] == "ipv6":
                        result = self.telegram_bot.cmd_add_ipv6([args[1]])
                        print(result)
                    else:
                        print("Usage: add [ip|ipv6] [ADDRESS]")
            
            elif cmd == "remove":
                if len(args) < 2:
                    print("Usage: remove [ip|ipv6] [ADDRESS]")
                else:
                    ip = args[1]
                    # Remove from config
                    if args[0] == "ip" and ip in self.config.config['monitoring']['ips']:
                        self.config.config['monitoring']['ips'].remove(ip)
                        self.config.save_config()
                        
                        # Update database
                        conn = sqlite3.connect(self.config.database_file)
                        cursor = conn.cursor()
                        cursor.execute(
                            "UPDATE monitored_ips SET status = 'Removed' WHERE ip = ?",
                            (ip,)
                        )
                        conn.commit()
                        conn.close()
                        
                        print(f"Removed IPv4 address {ip} from monitoring")
                    elif args[0] == "ipv6" and ip in self.config.config['monitoring']['ipv6s']:
                        self.config.config['monitoring']['ipv6s'].remove(ip)
                        self.config.save_config()
                        
                        # Update database
                        conn = sqlite3.connect(self.config.database_file)
                        cursor = conn.cursor()
                        cursor.execute(
                            "UPDATE monitored_ips SET status = 'Removed' WHERE ip = ?",
                            (ip,)
                        )
                        conn.commit()
                        conn.close()
                        
                        print(f"Removed IPv6 address {ip} from monitoring")
                    else:
                        print(f"IP address {ip} not found in monitoring list")
            
            elif cmd == "view":
                result = self.telegram_bot.cmd_view([])
                print(result)
            
            elif cmd == "ping":
                if len(args) < 2:
                    print("Usage: ping [ip|ipv6] [ADDRESS]")
                else:
                    if args[0] == "ip":
                        result = self.telegram_bot.cmd_ping_ip([args[1]])
                        print(result)
                    elif args[0] == "ipv6":
                        result = self.telegram_bot.cmd_ping_ipv6([args[1]])
                        print(result)
                    else:
                        print("Usage: ping [ip|ipv6] [ADDRESS]")
            
            elif cmd == "traceroute":
                if len(args) < 2:
                    print("Usage: traceroute [ip|ipv6] [ADDRESS]")
                else:
                    if args[0] == "ip":
                        result = self.telegram_bot.cmd_traceroute_ip([args[1]])
                        print(result)
                    elif args[0] == "ipv6":
                        result = self.telegram_bot.cmd_traceroute_ipv6([args[1]])
                        print(result)
                    else:
                        print("Usage: traceroute [ip|ipv6] [ADDRESS]")
            
            elif cmd == "udptraceroute":
                if len(args) < 1:
                    print("Usage: udptraceroute [ADDRESS]")
                else:
                    result = self.telegram_bot.cmd_udptraceroute([args[0]])
                    print(result)
            
            elif cmd == "tcptraceroute":
                if len(args) < 1:
                    print("Usage: tcptraceroute [ADDRESS]")
                else:
                    result = self.telegram_bot.cmd_tcptraceroute([args[0]])
                    print(result)
            
            elif cmd == "config":
                if len(args) < 3:
                    print("Usage: config telegram [chat_id|token] [VALUE]")
                else:
                    if args[0] == "telegram":
                        result = self.telegram_bot.cmd_config([f"telegram_{args[1]}", args[2]])
                        print(result)
                    else:
                        print("Usage: config telegram [chat_id|token] [VALUE]")
            
            elif cmd == "telegram":
                if len(args) < 1:
                    print("Usage: telegram [test|status]")
                else:
                    if args[0] == "test":
                        if self.telegram_bot.send_message("Test message from Cyber Security Monitoring Tool"):
                            print("Test message sent successfully")
                        else:
                            print("Failed to send test message")
                    elif args[0] == "status":
                        if self.telegram_bot.token and self.telegram_bot.chat_id:
                            print("Telegram is configured")
                        else:
                            print("Telegram is not configured")
                    else:
                        print("Usage: telegram [test|status]")
            
            elif cmd == "monitor":
                if len(args) < 1:
                    print("Usage: monitor [start|stop|status]")
                else:
                    if args[0] == "start":
                        if not self.security_monitor.monitoring:
                            monitor_thread = threading.Thread(target=self.security_monitor.start_monitoring)
                            monitor_thread.daemon = True
                            monitor_thread.start()
                            print("Monitoring started")
                        else:
                            print("Monitoring is already running")
                    elif args[0] == "stop":
                        self.security_monitor.stop_monitoring()
                        print("Monitoring stopped")
                    elif args[0] == "status":
                        result = self.telegram_bot.cmd_status([])
                        print(result)
                    else:
                        print("Usage: monitor [start|stop|status]")
            
            elif cmd == "logs":
                if len(args) < 1 or args[0] != "view":
                    print("Usage: logs view")
                else:
                    try:
                        conn = sqlite3.connect(self.config.database_file)
                        cursor = conn.cursor()
                        cursor.execute("SELECT log_type, source_ip, timestamp, details FROM security_logs ORDER BY id DESC LIMIT 20")
                        logs = cursor.fetchall()
                        conn.close()
                        
                        if not logs:
                            print("No security logs found")
                        else:
                            print("Recent Security Logs:")
                            for log_type, source_ip, timestamp, details in logs:
                                print(f"{timestamp[:19]} {log_type:15} {source_ip:15} {details}")
                    except Exception as e:
                        print(f"Error retrieving logs: {e}")
            
            elif cmd == "history":
                if len(args) == 0:
                    result = self.telegram_bot.cmd_history([])
                    print(result)
                elif len(args) == 1 and args[0] == "clear":
                    result = self.telegram_bot.cmd_clear([])
                    print(result)
                else:
                    print("Usage: history [clear]")
            
            else:
                print(f"Unknown command: {cmd}. Type 'help' for available commands.")
                return False
            
            self.log_command(command, True)
            return True
            
        except Exception as e:
            print(f"Error executing command: {e}")
            self.log_command(command, False)
            return False
    
    def start_cli(self) -> None:
        """Start the command line interface"""
        self.running = True
        self.print_banner()
        self.print_help()
        
        while self.running:
            try:
                prompt = f"{Fore.GREEN}accurate-cyber-defense>{Style.RESET_ALL} "
                command = input(prompt).strip()
                
                if command:
                    self.command_history.append(command)
                    self.execute_command(command)
            
            except KeyboardInterrupt:
                print("\nUse 'exit' or 'quit' to exit the program")
            
            except EOFError:
                self.running = False
        
        self.save_command_history()
        print("Exiting Accurate Cyber Defense Network Penerartion Testing Tool")

# ==============================
# MAIN APPLICATION
# ==============================
class CyberSecurityTool:
    """Main application class"""
    
    def __init__(self):
        # Initialize colorama for colored output
        from colorama import init, Fore, Style
        init()
        global Fore, Style
        Fore = Fore
        Style = Style
        
        self.config = Config()
        self.telegram_bot = TelegramBot(self.config)
        self.security_monitor = SecurityMonitor(self.config, self.telegram_bot)
        self.cli = CLI(self.config, self.telegram_bot, self.security_monitor)
    
    def start(self) -> None:
        """Start the application"""
        self.config.logger.info("Starting Cyber Security Monitoring Tool")
        
        # Start Telegram bot in a separate thread
        telegram_thread = threading.Thread(target=self.telegram_bot.start_bot)
        telegram_thread.daemon = True
        telegram_thread.start()
        
        # Start the CLI
        self.cli.start_cli()
        
        # Cleanup
        self.telegram_bot.stop_bot()
        self.security_monitor.stop_monitoring()
        self.config.logger.info("Accurate Cyber Defense Network Penetest Tool")

# ==============================
# DOCUMENTATION AND COMMUNITY
# ==============================
def show_documentation():
    """Show tool documentation"""
    docs = f"""
    {Fore.GREEN}Accurate Cyber Defense Network Cyber Security Monitoring Tool - Documentation{Style.RESET_ALL}
    
    This tool provides comprehensive IP-based cybersecurity monitoring with
    the following capabilities:
    
    {Fore.GREEN}1. IP Monitoring{Style.RESET_ALL}
      - Add IPv4 and IPv6 addresses for continuous monitoring
      - Regular checks for reachability and open ports
      - Threat level assessment based on open ports
    
    {Fore.GREEN}2. Network Diagnostics{Style.RESET_ALL}
      - Ping IPv4 and IPv6 addresses
      - Traceroute with UDP, TCP protocols
      - Port scanning for common services
    
    {Fore.GREEN}3. Telegram Integration{Style.RESET_ALL}
      - Remote control via Telegram bot
      - Security alerts sent to Telegram
      - Execute commands from anywhere
    
    {Fore.GREEN}4. Security Logging{Style.RESET_ALL}
      - Comprehensive logging of all activities
      - Security event tracking
      - Command history preservation
    
    {Fore.GREEN}5. Community & Support{Style.RESET_ALL}
      - GitHub repository: https://github.com/example/cyber-monitor
      - Documentation wiki: https://github.com/example/cyber-monitor/wiki
      - Issue tracker: https://github.com/example/cyber-monitor/issues
      - Discussion forum: https://github.com/example/cyber-monitor/discussions
    
    {Fore.GREEN}Getting Started:{Style.RESET_ALL}
      1. Configure Telegram bot token and chat ID
      2. Add IP addresses to monitor
      3. Start monitoring with 'monitor start'
      4. Use Telegram commands for remote management
    
    {Fore.GREEN}Best Practices:{Style.RESET_ALL}
      - Only monitor IP addresses you own or have permission to monitor
      - Regularly review security logs
      - Keep your Telegram chat ID secure
      - Use strong passwords for database protection
    """
    print(docs)

# ==============================
# MAIN ENTRY POINT
# ==============================
if __name__ == "__main__":
    # Check for documentation command
    if len(sys.argv) > 1 and sys.argv[1] == "docs":
        show_documentation()
        sys.exit(0)
    
    # Check for admin privileges
    if os.name != 'nt' and os.geteuid() != 0:
        print("This tool requires root privileges for some network operations.")
        print("Please run with sudo or as administrator.")
        sys.exit(1)
    
    # Start the application
    app = CyberSecurityTool()
    app.start()