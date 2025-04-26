import subprocess
import re
import os
import platform
import logging
from typing import List, Dict, Optional
import json

logger = logging.getLogger("wifi_passwords")

def is_admin() -> bool:
    """Check if the program is running with admin privileges"""
    try:
        if platform.system() == "Windows":
            # Try to create a protected directory
            os.makedirs("C:\\Windows\\Temp\\wifi_pass_check", exist_ok=True)
            os.rmdir("C:\\Windows\\Temp\\wifi_pass_check")
            return True
        else:
            # On Unix-like systems, check if UID is 0
            return os.geteuid() == 0
    except PermissionError:
        return False
    except Exception as e:
        logger.error(f"Error checking admin status: {str(e)}")
        return False

def get_wifi_profiles() -> List[str]:
    """Get list of saved WiFi profiles"""
    try:
        if not is_admin():
            raise PermissionError("Administrator/root privileges required")
            
        if platform.system() == "Windows":
            command = "netsh wlan show profiles"
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            
            profiles = []
            for line in result.stdout.split('\n'):
                if "All User Profile" in line:
                    profiles.append(line.split(":")[1].strip())
            return profiles
        
        elif platform.system() == "Linux":
            command = "sudo ls /etc/NetworkManager/system-connections/"
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            return [f.replace('.nmconnection', '') for f in result.stdout.split('\n') if f.endswith('.nmconnection')]
        
        elif platform.system() == "Darwin":  # macOS
            command = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s"
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            
            profiles = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    profiles.append(line.split()[0])
            return profiles
            
    except Exception as e:
        logger.error(f"Error getting WiFi profiles: {str(e)}")
        return []

def get_wifi_password(profile_name: str) -> Dict[str, str]:
    """Get password for a specific WiFi profile"""
    try:
        if not is_admin():
            raise PermissionError("Administrator/root privileges required")
            
        if platform.system() == "Windows":
            command = f'netsh wlan show profile name="{profile_name}" key=clear'
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            
            password = None
            security = "Unknown"
            for line in result.stdout.split('\n'):
                if "Key Content" in line:
                    password = line.split(":")[1].strip()
                elif "Authentication" in line:
                    security = line.split(":")[1].strip()
            
            return {
                "profile": profile_name,
                "password": password if password else "Not available",
                "security": security
            }
        
        elif platform.system() == "Linux":
            file_path = f"/etc/NetworkManager/system-connections/{profile_name}.nmconnection"
            command = f"sudo cat {file_path}"
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            
            password = None
            security = "Unknown"
            for line in result.stdout.split('\n'):
                if "psk=" in line:
                    password = line.split("=")[1].strip().strip('"')
                elif "key-mgmt=" in line:
                    security = line.split("=")[1].strip().upper()
            
            return {
                "profile": profile_name,
                "password": password if password else "Not available",
                "security": security
            }
        
        elif platform.system() == "Darwin":  # macOS
            command = f"security find-generic-password -ga '{profile_name}' 2>&1 | grep 'password:'"
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            
            password = None
            if "password:" in result.stdout:
                password = result.stdout.split("password:")[1].strip().strip('"')
            
            # Get security type
            sec_command = f"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I"
            sec_result = subprocess.run(sec_command, capture_output=True, text=True, shell=True)
            security = "Unknown"
            if sec_result.returncode == 0:
                for line in sec_result.stdout.split('\n'):
                    if "auth type" in line.lower():
                        security = line.split(":")[1].strip()
            
            return {
                "profile": profile_name,
                "password": password if password else "Not available",
                "security": security
            }
            
    except Exception as e:
        logger.error(f"Error getting WiFi password for {profile_name}: {str(e)}")
        return {
            "profile": profile_name,
            "password": f"Error: {str(e)}",
            "security": "Error"
        }

def get_current_wifi() -> Optional[Dict[str, str]]:
    """Get currently connected WiFi network"""
    try:
        if platform.system() == "Windows":
            command = "netsh wlan show interfaces"
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                return None
                
            current_ssid = None
            for line in result.stdout.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    current_ssid = line.split(":")[1].strip()
                    break
            
            if current_ssid and current_ssid != "":
                return get_wifi_password(current_ssid)
        
        elif platform.system() in ["Linux", "Darwin"]:
            if platform.system() == "Linux":
                command = "iwgetid -r"
            else:  # macOS
                command = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/ SSID/ {print substr($0, index($0, $2))}'"
            
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode == 0 and result.stdout.strip():
                return get_wifi_password(result.stdout.strip())
                
        return None
    except Exception as e:
        logger.error(f"Error getting current WiFi: {str(e)}")
        return None
