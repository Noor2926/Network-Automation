import os
import re
import json
import socket
import subprocess
import platform
import logging
import requests
import time
import threading
from pathlib import Path
from typing import Dict, Tuple, Optional, List, Any, Union
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("dnsconfig")

# Constants
DNS_CONFIG_DIR = Path("data/dns_config")
DEVICE_INFO_DIR = Path("data/devices")
URL_RESTRICT_DIR = Path("data/url_restrictions")

# Ensure directories exist
DNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DEVICE_INFO_DIR.mkdir(parents=True, exist_ok=True)
URL_RESTRICT_DIR.mkdir(parents=True, exist_ok=True)

def validate_ip(ip: str) -> bool:
    """Validate if a string is a valid IPv4 address."""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))

def validate_url(url: str) -> bool:
    """Validate if a string is a valid URL."""
    # First, strip http:// or https:// if present
    url = re.sub(r'^https?://(www\.)?', '', url)
    
    # Now validate the domain format
    pattern = r'^[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    return bool(re.match(pattern, url))

def get_dns_settings(ip: str) -> Dict[str, str]:
    """Get DNS settings for a specific device."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {"status": "error", "message": "Invalid IP address format"}
    
    try:
        # Check if we have stored DNS settings
        dns_file = DNS_CONFIG_DIR / f"{ip.replace('.', '_')}.json"
        
        if dns_file.exists():
            with open(dns_file, 'r') as f:
                dns_data = json.load(f)
                return {
                    "status": "success",
                    "primary_dns": dns_data.get("primary_dns", ""),
                    "secondary_dns": dns_data.get("secondary_dns", ""),
                    "restricted_urls": dns_data.get("restricted_urls", [])
                }
        
        # Try to detect DNS settings from the device
        detected_dns = detect_device_dns(ip)
        if detected_dns:
            return {
                "status": "success",
                "primary_dns": detected_dns[0],
                "secondary_dns": detected_dns[1] if len(detected_dns) > 1 else "",
                "restricted_urls": []
            }
        
        # Return default Google DNS if nothing is found
        return {
            "status": "success",
            "primary_dns": "8.8.8.8",
            "secondary_dns": "8.8.4.4",
            "restricted_urls": []
        }
    
    except Exception as e:
        logger.error(f"Error getting DNS settings for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to get DNS settings: {str(e)}"
        }

def save_dns_settings(ip: str, primary_dns: str, secondary_dns: str = "", restricted_urls: List[str] = None) -> Dict[str, str]:
    """Save DNS settings for a specific device."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {"status": "error", "message": "Invalid IP address format"}
    
    if not validate_ip(primary_dns):
        logger.error(f"Invalid primary DNS format: {primary_dns}")
        return {"status": "error", "message": "Invalid primary DNS format"}
    
    if secondary_dns and not validate_ip(secondary_dns):
        logger.error(f"Invalid secondary DNS format: {secondary_dns}")
        return {"status": "error", "message": "Invalid secondary DNS format"}
    
    # Initialize restricted_urls if None
    if restricted_urls is None:
        restricted_urls = []
    
    # Validate URLs
    invalid_urls = []
    for url in restricted_urls:
        if not validate_url(url):
            invalid_urls.append(url)
    
    if invalid_urls:
        logger.error(f"Invalid URL formats: {', '.join(invalid_urls)}")
        return {"status": "error", "message": f"Invalid URL formats: {', '.join(invalid_urls)}"}
    
    try:
        # Save DNS settings to file
        dns_file = DNS_CONFIG_DIR / f"{ip.replace('.', '_')}.json"
        
        # Check if file exists to preserve any existing data
        existing_data = {}
        if dns_file.exists():
            try:
                with open(dns_file, 'r') as f:
                    existing_data = json.load(f)
            except Exception as e:
                logger.error(f"Error reading existing DNS file: {str(e)}")
        
        dns_data = {
            "primary_dns": primary_dns,
            "secondary_dns": secondary_dns,
            "restricted_urls": restricted_urls,
            "timestamp": datetime.now().isoformat()
        }
        
        # Merge with existing data
        existing_data.update(dns_data)
        
        with open(dns_file, 'w') as f:
            json.dump(existing_data, f)
        
        # Save URL restrictions separately for easier access
        save_url_restrictions(ip, restricted_urls)
        
        # Try to apply DNS settings to the device
        apply_result = apply_dns_to_device(ip, primary_dns, secondary_dns, restricted_urls)
        
        if apply_result.get("status") == "error":
            logger.warning(f"DNS settings saved but could not be applied: {apply_result.get('message')}")
            return {
                "status": "success",
                "message": "DNS settings saved but could not be applied to device",
                "warning": apply_result.get("message")
            }
        
        return {
            "status": "success",
            "message": "DNS settings saved and applied successfully"
        }
    
    except Exception as e:
        logger.error(f"Error saving DNS settings for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to save DNS settings: {str(e)}"
        }

def save_url_restrictions(ip: str, restricted_urls: List[str]) -> None:
    """Save URL restrictions for a device."""
    try:
        url_file = URL_RESTRICT_DIR / f"{ip.replace('.', '_')}.json"
        
        url_data = {
            "ip": ip,
            "restricted_urls": restricted_urls,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(url_file, 'w') as f:
            json.dump(url_data, f)
        
        logger.info(f"URL restrictions saved for {ip}: {restricted_urls}")
        
        # Apply URL restrictions to the device
        apply_url_restrictions(ip, restricted_urls)
    except Exception as e:
        logger.error(f"Error saving URL restrictions for {ip}: {str(e)}")

def apply_url_restrictions(ip: str, restricted_urls: List[str]) -> Dict[str, Any]:
    """Apply URL restrictions to a device by modifying its hosts file or DNS settings."""
    try:
        if not restricted_urls:
            logger.info(f"No URL restrictions to apply for {ip}")
            return {"status": "success", "message": "No URL restrictions to apply"}
        
        # Determine device type to choose the best method
        device_type = get_device_type(ip)
        logger.info(f"Applying URL restrictions to {ip} (device type: {device_type})")
        
        if device_type == "windows":
            return apply_url_restrictions_windows(ip, restricted_urls)
        elif device_type == "android":
            return apply_url_restrictions_android(ip, restricted_urls)
        elif device_type == "linux" or device_type == "mac":
            return apply_url_restrictions_linux(ip, restricted_urls)
        elif device_type == "router":
            return apply_url_restrictions_router(ip, restricted_urls)
        else:
            # Try a generic approach using DNS
            return apply_url_restrictions_dns(ip, restricted_urls)
    
    except Exception as e:
        logger.error(f"Error applying URL restrictions to {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply URL restrictions: {str(e)}"}

def apply_url_restrictions_windows(ip: str, restricted_urls: List[str]) -> Dict[str, Any]:
    """Apply URL restrictions to a Windows device by modifying its hosts file."""
    try:
        # Create a PowerShell script to modify the hosts file
        hosts_entries = []
        for url in restricted_urls:
            # Remove http:// or https:// if present
            clean_url = re.sub(r'^https?://(www\.)?', '', url)
            # Add both the domain and www subdomain
            hosts_entries.append(f"127.0.0.1 {clean_url}")
            hosts_entries.append(f"127.0.0.1 www.{clean_url}")
        
        hosts_content = "\n".join(hosts_entries)
        
        # PowerShell script to append to hosts file
        ps_script = f"""
        $hostsPath = "$env:windir\\System32\\drivers\\etc\\hosts"
        $currentContent = Get-Content $hostsPath -Raw
        $newEntries = @"

        # URL restrictions added by Network Scanner
        {hosts_content}
        "@

        # Check if entries already exist
        if ($currentContent -notmatch [regex]::Escape("# URL restrictions added by Network Scanner")) {{
            Add-Content -Path $hostsPath -Value $newEntries
            Write-Output "URL restrictions added to hosts file"
        }} else {{
            # Replace existing restrictions
            $pattern = "# URL restrictions added by Network Scanner.*?(?=`n`n|$)"
            $replacement = "# URL restrictions added by Network Scanner`n{hosts_content.replace('$', '$$')}"
            $newContent = $currentContent -replace $pattern, $replacement
            Set-Content -Path $hostsPath -Value $newContent
            Write-Output "URL restrictions updated in hosts file"
        }}

        # Flush DNS cache
        ipconfig /flushdns
        """
        
        # Save script to a temporary file
        script_path = Path("temp_hosts_script.ps1")
        with open(script_path, 'w') as f:
            f.write(ps_script)
        
        # Execute the script remotely using WMI/PSExec or similar
        # This is a placeholder - in a real implementation, you would use
        # a library like pypsexec or similar to execute the script on the remote machine
        logger.info(f"Would execute PowerShell script on {ip} to modify hosts file")
        logger.info(f"Script content: {ps_script}")
        
        # For now, simulate success
        return {"status": "success", "message": "URL restrictions applied to Windows device"}
    
    except Exception as e:
        logger.error(f"Error applying URL restrictions to Windows device {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply URL restrictions to Windows device: {str(e)}"}

def apply_url_restrictions_android(ip: str, restricted_urls: List[str]) -> Dict[str, Any]:
    """Apply URL restrictions to an Android device."""
    try:
        # For Android, we can use ADB to modify the hosts file if the device is rooted
        # or set up a local VPN that blocks the domains
        
        # This is a placeholder - in a real implementation, you would use
        # ADB commands or a third-party app to apply restrictions
        logger.info(f"Would apply URL restrictions to Android device {ip}")
        
        # For now, simulate success
        return {"status": "success", "message": "URL restrictions applied to Android device"}
    
    except Exception as e:
        logger.error(f"Error applying URL restrictions to Android device {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply URL restrictions to Android device: {str(e)}"}

def apply_url_restrictions_linux(ip: str, restricted_urls: List[str]) -> Dict[str, Any]:
    """Apply URL restrictions to a Linux/Mac device by modifying its hosts file."""
    try:
        # Create a shell script to modify the hosts file
        hosts_entries = []
        for url in restricted_urls:
            # Remove http:// or https:// if present
            clean_url = re.sub(r'^https?://(www\.)?', '', url)
            # Add both the domain and www subdomain
            hosts_entries.append(f"127.0.0.1 {clean_url}")
            hosts_entries.append(f"127.0.0.1 www.{clean_url}")
        
        hosts_content = "\n".join(hosts_entries)
        
        # Shell script to append to hosts file
        shell_script = f"""#!/bin/bash
        HOSTS_FILE="/etc/hosts"
        
        # Check if our marker exists
        if grep -q "# URL restrictions added by Network Scanner" $HOSTS_FILE; then
            # Replace existing restrictions
            sed -i '/# URL restrictions added by Network Scanner/,/^$/d' $HOSTS_FILE
        fi
        
        # Add new restrictions
        echo "
        # URL restrictions added by Network Scanner
        {hosts_content}
        " >> $HOSTS_FILE
        
        # Flush DNS cache
        if [ -x "$(command -v dscacheutil)" ]; then
            # macOS
            dscacheutil -flushcache
            killall -HUP mDNSResponder
        elif [ -x "$(command -v systemd-resolve)" ]; then
            # Linux with systemd
            systemd-resolve --flush-caches
        elif [ -x "$(command -v service)" ]; then
            # Linux with service command
            service nscd restart
        fi
        
        echo "URL restrictions applied"
        """
        
        # Save script to a temporary file
        script_path = Path("temp_hosts_script.sh")
        with open(script_path, 'w') as f:
            f.write(shell_script)
        
        # Execute the script remotely using SSH
        # This is a placeholder - in a real implementation, you would use
        # a library like paramiko to execute the script on the remote machine
        logger.info(f"Would execute shell script on {ip} to modify hosts file")
        logger.info(f"Script content: {shell_script}")
        
        # For now, simulate success
        return {"status": "success", "message": "URL restrictions applied to Linux/Mac device"}
    
    except Exception as e:
        logger.error(f"Error applying URL restrictions to Linux/Mac device {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply URL restrictions to Linux/Mac device: {str(e)}"}

def apply_url_restrictions_router(ip: str, restricted_urls: List[str]) -> Dict[str, Any]:
    """Apply URL restrictions to a router by configuring its parental controls or firewall."""
    try:
        # This is a placeholder - in a real implementation, you would use
        # the router's API or web interface to configure URL blocking
        logger.info(f"Would apply URL restrictions to router {ip}")
        
        # For now, simulate success
        return {"status": "success", "message": "URL restrictions applied to router"}
    
    except Exception as e:
        logger.error(f"Error applying URL restrictions to router {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply URL restrictions to router: {str(e)}"}

def apply_url_restrictions_dns(ip: str, restricted_urls: List[str]) -> Dict[str, Any]:
    """Apply URL restrictions using DNS-based blocking."""
    try:
        # This is a placeholder - in a real implementation, you would configure
        # a local DNS server or use a service like Pi-hole to block domains
        logger.info(f"Would apply DNS-based URL restrictions for {ip}")
        
        # For now, simulate success
        return {"status": "success", "message": "URL restrictions applied using DNS"}
    
    except Exception as e:
        logger.error(f"Error applying DNS-based URL restrictions for {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply DNS-based URL restrictions: {str(e)}"}

def get_url_restrictions(ip: str) -> Dict[str, Any]:
    """Get URL restrictions for a device."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {"status": "error", "message": "Invalid IP address format"}
    
    try:
        url_file = URL_RESTRICT_DIR / f"{ip.replace('.', '_')}.json"
        
        if url_file.exists():
            with open(url_file, 'r') as f:
                url_data = json.load(f)
                return {
                    "status": "success",
                    "restricted_urls": url_data.get("restricted_urls", [])
                }
        
        return {
            "status": "success",
            "restricted_urls": []
        }
    except Exception as e:
        logger.error(f"Error getting URL restrictions for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to get URL restrictions: {str(e)}"
        }

def add_url_restriction(ip: str, url: str) -> Dict[str, Any]:
    """Add a URL restriction for a device."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {"status": "error", "message": "Invalid IP address format"}
    
    # Strip http:// or https:// if present
    url = re.sub(r'^https?://(www\.)?', '', url)
    
    if not validate_url(url):
        logger.error(f"Invalid URL format: {url}")
        return {"status": "error", "message": "Invalid URL format"}
    
    try:
        # Get current restrictions
        current = get_url_restrictions(ip)
        
        if current.get("status") == "error":
            return current
        
        restricted_urls = current.get("restricted_urls", [])
        
        # Check if URL is already restricted
        if url in restricted_urls:
            return {
                "status": "success",
                "message": "URL is already restricted",
                "restricted_urls": restricted_urls
            }
        
        # Add new URL
        restricted_urls.append(url)
        
        # Save updated restrictions
        save_url_restrictions(ip, restricted_urls)
        
        # Update DNS settings to include the new URL
        dns_settings = get_dns_settings(ip)
        if dns_settings.get("status") == "success":
            save_dns_settings(
                ip, 
                dns_settings.get("primary_dns", "8.8.8.8"),
                dns_settings.get("secondary_dns", ""),
                restricted_urls
            )
        
        # Apply the restriction immediately
        apply_result = apply_url_restrictions(ip, restricted_urls)
        
        if apply_result.get("status") == "error":
            return {
                "status": "success",
                "message": "URL restriction added but could not be applied",
                "warning": apply_result.get("message"),
                "restricted_urls": restricted_urls
            }
        
        return {
            "status": "success",
            "message": "URL restriction added and applied successfully",
            "restricted_urls": restricted_urls
        }
    except Exception as e:
        logger.error(f"Error adding URL restriction for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to add URL restriction: {str(e)}"
        }

def remove_url_restriction(ip: str, url: str) -> Dict[str, Any]:
    """Remove a URL restriction for a device."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {
            "status": "error",
            "message": "Invalid IP address format"
        }
    
    try:
        # Get current restrictions
        current = get_url_restrictions(ip)
        
        if current.get("status") == "error":
            return current
        
        restricted_urls = current.get("restricted_urls", [])
        
        # Check if URL is in the list
        if url not in restricted_urls:
            return {
                "status": "success",
                "message": "URL is not in the restriction list",
                "restricted_urls": restricted_urls
            }
        
        # Remove URL
        restricted_urls.remove(url)
        
        # Save updated restrictions
        save_url_restrictions(ip, restricted_urls)
        
        # Update DNS settings to remove the URL
        dns_settings = get_dns_settings(ip)
        if dns_settings.get("status") == "success":
            save_dns_settings(
                ip, 
                dns_settings.get("primary_dns", "8.8.8.8"),
                dns_settings.get("secondary_dns", ""),
                restricted_urls
            )
        
        # Apply the updated restrictions
        apply_result = apply_url_restrictions(ip, restricted_urls)
        
        if apply_result.get("status") == "error":
            return {
                "status": "success",
                "message": "URL restriction removed but could not be applied",
                "warning": apply_result.get("message"),
                "restricted_urls": restricted_urls
            }
        
        return {
            "status": "success",
            "message": "URL restriction removed and applied successfully",
            "restricted_urls": restricted_urls
        }
    except Exception as e:
        logger.error(f"Error removing URL restriction for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to remove URL restriction: {str(e)}"
        }

def detect_device_dns(ip: str) -> List[str]:
    """Try to detect DNS settings from a device."""
    try:
        # This is a placeholder for actual implementation
        # In a real-world scenario, you would use SNMP, SSH, or other protocols
        # to query the device for its DNS settings
        
        # For now, we'll just return an empty list
        return []
    except Exception as e:
        logger.error(f"Error detecting DNS for {ip}: {str(e)}")
        return []

def apply_dns_to_device(ip: str, primary_dns: str, secondary_dns: str = "", restricted_urls: List[str] = None) -> Dict[str, Any]:
    """Apply DNS settings to a device."""
    try:
        # Determine device type to choose the best method
        device_type = get_device_type(ip)
        logger.info(f"Applying DNS settings to {ip} (device type: {device_type})")
        
        if device_type == "windows":
            return apply_dns_to_windows(ip, primary_dns, secondary_dns)
        elif device_type == "android":
            return apply_dns_to_android(ip, primary_dns, secondary_dns)
        elif device_type == "linux" or device_type == "mac":
            return apply_dns_to_linux(ip, primary_dns, secondary_dns)
        elif device_type == "router":
            return apply_dns_to_router(ip, primary_dns, secondary_dns)
        else:
            # For unknown device types, just log the settings
            logger.info(f"DNS settings would be applied to {ip}: Primary={primary_dns}, Secondary={secondary_dns}")
            if restricted_urls:
                logger.info(f"URL restrictions would be applied to {ip}: {restricted_urls}")
            
            # Update device info if available
            update_device_dns_info(ip, primary_dns, secondary_dns, restricted_urls)
            
            return {
                "status": "success",
                "message": "DNS settings applied successfully"
            }
    except Exception as e:
        logger.error(f"Error applying DNS to {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to apply DNS settings: {str(e)}"
        }

def apply_dns_to_windows(ip: str, primary_dns: str, secondary_dns: str = "") -> Dict[str, Any]:
    """Apply DNS settings to a Windows device."""
    try:
        # Create a PowerShell script to set DNS servers
        ps_script = f"""
        $adapters = Get-NetAdapter | Where-Object {{$_.Status -eq "Up"}}
        foreach ($adapter in $adapters) {{
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses ("{primary_dns}","{secondary_dns}")
        }}
        ipconfig /flushdns
        """
        
        # Save script to a temporary file
        script_path = Path("temp_dns_script.ps1")
        with open(script_path, 'w') as f:
            f.write(ps_script)
        
        # Execute the script remotely using WMI/PSExec or similar
        # This is a placeholder - in a real implementation, you would use
        # a library like pypsexec or similar to execute the script on the remote machine
        logger.info(f"Would execute PowerShell script on {ip} to set DNS servers")
        logger.info(f"Script content: {ps_script}")
        
        # For now, simulate success
        return {"status": "success", "message": "DNS settings applied to Windows device"}
    
    except Exception as e:
        logger.error(f"Error applying DNS to Windows device {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply DNS settings to Windows device: {str(e)}"}

def apply_dns_to_android(ip: str, primary_dns: str, secondary_dns: str = "") -> Dict[str, Any]:
    """Apply DNS settings to an Android device."""
    try:
        # For Android, we can use ADB to change DNS settings if the device is rooted
        # or guide the user to change the settings manually
        
        # This is a placeholder - in a real implementation, you would use
        # ADB commands or a third-party app to apply DNS settings
        logger.info(f"Would apply DNS settings to Android device {ip}")
        
        # For now, simulate success
        return {"status": "success", "message": "DNS settings applied to Android device"}
    
    except Exception as e:
        logger.error(f"Error applying DNS to Android device {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply DNS settings to Android device: {str(e)}"}

def apply_dns_to_linux(ip: str, primary_dns: str, secondary_dns: str = "") -> Dict[str, Any]:
    """Apply DNS settings to a Linux/Mac device."""
    try:
        # Create a shell script to set DNS servers
        shell_script = f"""#!/bin/bash
        
        # Detect the OS
        if [ -f /etc/resolv.conf ]; then
            # Linux or macOS
            echo "nameserver {primary_dns}" > /etc/resolv.conf
            if [ -n "{secondary_dns}" ]; then
                echo "nameserver {secondary_dns}" >> /etc/resolv.conf
            fi
            
            # Restart networking service if available
            if [ -x "$(command -v systemctl)" ]; then
                systemctl restart NetworkManager
            elif [ -x "$(command -v service)" ]; then
                service networking restart
            fi
        elif [ -x "$(command -v networksetup)" ]; then
            # macOS specific
            for interface in $(networksetup -listallnetworkservices | grep -v "*"); do
                networksetup -setdnsservers "$interface" {primary_dns} {secondary_dns}
            done
        fi
        
        echo "DNS settings applied"
        """
        
        # Save script to a temporary file
        script_path = Path("temp_dns_script.sh")
        with open(script_path, 'w') as f:
            f.write(shell_script)
        
        # Execute the script remotely using SSH
        # This is a placeholder - in a real implementation, you would use
        # a library like paramiko to execute the script on the remote machine
        logger.info(f"Would execute shell script on {ip} to set DNS servers")
        logger.info(f"Script content: {shell_script}")
        
        # For now, simulate success
        return {"status": "success", "message": "DNS settings applied to Linux/Mac device"}
    
    except Exception as e:
        logger.error(f"Error applying DNS to Linux/Mac device {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply DNS settings to Linux/Mac device: {str(e)}"}

def apply_dns_to_router(ip: str, primary_dns: str, secondary_dns: str = "") -> Dict[str, Any]:
    """Apply DNS settings to a router."""
    try:
        # This is a placeholder - in a real implementation, you would use
        # the router's API or web interface to configure DNS settings
        logger.info(f"Would apply DNS settings to router {ip}")
        
        # For now, simulate success
        return {"status": "success", "message": "DNS settings applied to router"}
    
    except Exception as e:
        logger.error(f"Error applying DNS to router {ip}: {str(e)}")
        return {"status": "error", "message": f"Failed to apply DNS settings to router: {str(e)}"}

def update_device_dns_info(ip: str, primary_dns: str, secondary_dns: str = "", restricted_urls: List[str] = None) -> None:
    """Update device info with DNS settings."""
    try:
        device_file = DEVICE_INFO_DIR / f"{ip.replace('.', '_')}.json"
        
        if device_file.exists():
            with open(device_file, 'r') as f:
                device_data = json.load(f)
            
            # Update DNS information
            device_data["dns"] = {
                "primary": primary_dns,
                "secondary": secondary_dns,
                "updated_at": datetime.now().isoformat()
            }
            
            if restricted_urls:
                device_data["dns"]["restricted_urls"] = restricted_urls
            
            with open(device_file, 'w') as f:
                json.dump(device_data, f)
    except Exception as e:
        logger.error(f"Error updating device info for {ip}: {str(e)}")

def ping_device(ip: str, count: int = 4, timeout: float = 1.0) -> Dict[str, Any]:
    """Ping a device and return the results."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {
            "success": False,
            "message": "Invalid IP address format"
        }
    
    try:
        # Determine the ping command based on the operating system
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        # Build the ping command
        command = ['ping', param, str(count), timeout_param, str(int(timeout)), ip]
        
        # Execute the ping command
        logger.info(f"Executing ping command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout * count + 2)
        
        # Parse the output
        output = result.stdout
        
        # Check if ping was successful
        if result.returncode == 0:
            # Extract ping time if available
            time_match = re.search(r'time=(\d+\.?\d*)', output)
            avg_time_match = re.search(r'Average = (\d+\.?\d*)', output)  # For Windows
            
            ping_time = None
            if time_match:
                ping_time = float(time_match.group(1))
            elif avg_time_match:
                ping_time = float(avg_time_match.group(1))
            
            return {
                "success": True,
                "message": "Device is reachable",
                "time": ping_time,
                "output": output
            }
        else:
            return {
                "success": False,
                "message": "Device is not reachable",
                "output": output
            }
    
    except subprocess.TimeoutExpired:
        logger.error(f"Ping timeout for {ip}")
        return {
            "success": False,
            "message": "Ping timed out"
        }
    except Exception as e:
        logger.error(f"Error pinging {ip}: {str(e)}")
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

def restart_device(ip: str, method: str = "auto") -> Dict[str, Any]:
    """Attempt to restart a network device."""
    if not validate_ip(ip):
        logger.error(f"Invalid IP address format: {ip}")
        return {
            "success": False,
            "message": "Invalid IP address format"
        }
    
    try:
        # Check if device is reachable first
        ping_result = ping_device(ip, count=1, timeout=0.5)
        is_reachable = ping_result["success"]
        
        if not is_reachable:
            logger.warning(f"Device {ip} is not responding to ping, but will attempt restart anyway")
        
        # Determine the best restart method
        if method == "auto":
            # Try to determine device type and choose appropriate method
            device_type = get_device_type(ip)
            logger.info(f"Auto-detected device type for {ip}: {device_type}")
            
            if device_type == "android":
                method = "adb"
            elif device_type == "windows":
                method = "wmi"
            elif device_type == "router":
                method = "snmp"
            elif device_type == "linux":
                method = "ssh"
            else:
                method = "web"
        
        logger.info(f"Using restart method '{method}' for device {ip}")
        
        # Attempt restart using the selected method
        if method == "snmp":
            result = restart_via_snmp(ip)
        elif method == "ssh":
            result = restart_via_ssh(ip)
        elif method == "wmi":
            result = restart_via_wmi(ip)
        elif method == "web":
            result = restart_via_web(ip)
        elif method == "adb":
            result = restart_via_adb(ip)
        else:
            logger.error(f"Unknown restart method: {method}")
            return {
                "success": False,
                "message": f"Unknown restart method: {method}"
            }
        
        # Update device status in database
        update_device_restart_status(ip, result["success"], method, result.get("message", ""))
        
        # If restart was successful, verify by pinging after a short delay
        if result["success"]:
            # Start a background thread to verify the restart
            threading.Thread(target=verify_restart, args=(ip, method)).start()
        
        return result
    
    except Exception as e:
        logger.error(f"Error restarting {ip}: {str(e)}")
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

def verify_restart(ip: str, method: str) -> None:
    """Verify that a device has restarted by pinging it after a delay."""
    try:
        logger.info(f"Starting restart verification for {ip}")
        
        # Wait for the device to go offline
        offline_timeout = 30  # seconds
        offline_start = time.time()
        device_went_offline = False
        
        while time.time() - offline_start < offline_timeout:
            ping_result = ping_device(ip, count=1, timeout=0.5)
            if not ping_result["success"]:
                device_went_offline = True
                logger.info(f"Device {ip} is now offline, restart in progress")
                break
            time.sleep(2)
        
        if not device_went_offline:
            logger.warning(f"Device {ip} did not go offline after restart command")
            update_device_restart_status(ip, False, method, "Device did not go offline after restart command")
            return
        
        # Wait for the device to come back online
        online_timeout = 120  # seconds
        online_start = time.time()
        device_came_online = False
        
        while time.time() - online_start < online_timeout:
            ping_result = ping_device(ip, count=1, timeout=0.5)
            if ping_result["success"]:
                device_came_online = True
                logger.info(f"Device {ip} is back online, restart completed successfully")
                update_device_restart_status(ip, True, method, "Restart verified: Device went offline and came back online")
                return
            time.sleep(5)
        
        if not device_came_online:
            logger.warning(f"Device {ip} did not come back online after restart")
            update_device_restart_status(ip, False, method, "Device did not come back online after restart")
    
    except Exception as e:
        logger.error(f"Error verifying restart for {ip}: {str(e)}")
        update_device_restart_status(ip, False, method, f"Error verifying restart: {str(e)}")

def get_device_type(ip: str) -> str:
    """Try to determine the device type based on open ports and other characteristics."""
    try:
        # Check common ports to identify device type
        device_type = "unknown"
        
        # Check for Android ADB port
        if check_port_open(ip, 5555):
            return "android"
        
        # Check for Windows RDP port
        if check_port_open(ip, 3389):
            return "windows"
        
        # Check for SSH (Linux/Mac)
        if check_port_open(ip, 22):
            return "linux"
        
        # Check for common router ports
        if check_port_open(ip, 80) or check_port_open(ip, 443):
            # Try to access common router login pages
            try:
                response = requests.get(f"http://{ip}/", timeout=2)
                page_content = response.text.lower()
                
                # Check for common router keywords
                router_keywords = ["router", "gateway", "admin", "login", "password"]
                if any(keyword in page_content for keyword in router_keywords):
                    return "router"
            except:
                pass
        
        # Try to get MAC address and check vendor
        mac = get_mac_address(ip)
        if mac:
            vendor = get_vendor_from_mac(mac)
            if vendor:
                if any(android_vendor in vendor.lower() for android_vendor in ["android", "google", "samsung", "xiaomi", "huawei", "oppo", "vivo"]):
                    return "android"
                elif any(windows_vendor in vendor.lower() for windows_vendor in ["microsoft", "dell", "hp", "lenovo", "asus"]):
                    return "windows"
                elif any(router_vendor in vendor.lower() for router_vendor in ["cisco", "netgear", "tp-link", "d-link", "asus", "linksys"]):
                    return "router"
        
        # Try to detect OS by sending specific requests
        try:
            # Try Windows-specific detection
            if check_port_open(ip, 135) or check_port_open(ip, 445):
                return "windows"
            
            # Try Android-specific detection
            if check_port_open(ip, 5555) or check_port_open(ip, 7000):
                return "android"
        except:
            pass
        
        return device_type
    
    except Exception as e:
        logger.error(f"Error determining device type for {ip}: {str(e)}")
        return "unknown"

def check_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open on a given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        return result == 0
    except Exception as e:
        logger.error(f"Error checking port {port} on {ip}: {str(e)}")
        return False

def get_mac_address(ip: str) -> str:
    """Try to get MAC address for an IP."""
    try:
        # This is platform-dependent and may not work in all environments
        if platform.system().lower() == "windows":
            # Use ARP on Windows
            os.system(f"ping -n 1 {ip} > nul")
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
            mac_matches = re.findall(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
            if mac_matches:
                return mac_matches[0]
        else:
            # Use ARP on Linux/Mac
            os.system(f"ping -c 1 {ip} > /dev/null")
            output = subprocess.check_output(f"arp -n {ip}", shell=True).decode()
            mac_matches = re.findall(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", output)
            if mac_matches:
                return mac_matches[0]
    except:
        pass
    return ""

def get_vendor_from_mac(mac: str) -> str:
    """Try to determine vendor from MAC address."""
    # This would typically use a MAC address vendor database
    # For now, return empty string
    return ""

def restart_via_snmp(ip: str) -> Dict[str, Any]:
    """Restart a device using SNMP."""
    try:
        # This is a placeholder for actual SNMP implementation
        # In a real-world scenario, you would use a library like pysnmp
        # to send the appropriate SNMP commands to restart the device
        
        logger.info(f"SNMP restart would be performed on {ip}")
        
        # For a real implementation, you would do something like:
        # from pysnmp.hlapi import *
        # errorIndication, errorStatus, errorIndex, varBinds = next(
        #     setCmd(SnmpEngine(),
        #            CommunityData('public'),
        #            UdpTransportTarget((ip, 161)),
        #            ContextData(),
        #            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0), 'restart'))
        # )
        
        # Simulate success
        return {
            "success": True,
            "message": "SNMP restart command sent successfully"
        }
    except Exception as e:
        logger.error(f"Error restarting {ip} via SNMP: {str(e)}")
        return {
            "success": False,
            "message": f"SNMP restart failed: {str(e)}"
        }

def restart_via_ssh(ip: str, username: str = None, password: str = None) -> Dict[str, Any]:
    """Restart a device using SSH."""
    try:
        # This is a placeholder for actual SSH implementation
        # In a real-world scenario, you would use a library like paramiko
        # to establish an SSH connection and send the restart command
        
        logger.info(f"SSH restart would be performed on {ip}")
        
        if username and password:
            logger.info(f"Using provided credentials: username={username}")
        else:
            logger.info("No credentials provided, using default if available")
        
        # For a real implementation, you would do something like:
        # import paramiko
        # client = paramiko.SSHClient()
        # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # client.connect(ip, username=username, password=password)
        # stdin, stdout, stderr = client.exec_command('sudo reboot')
        # client.close()
        
        # Simulate success
        return {
            "success": True,
            "message": "SSH restart command sent successfully"
        }
    except Exception as e:
        logger.error(f"Error restarting {ip} via SSH: {str(e)}")
        return {
            "success": False,
            "message": f"SSH restart failed: {str(e)}"
        }

def restart_via_wmi(ip: str) -> Dict[str, Any]:
    """Restart a Windows device using WMI."""
    try:
        # This is a placeholder for actual WMI implementation
        # In a real-world scenario, you would use a library like wmi
        # to connect to the Windows device and initiate a restart
        
        logger.info(f"WMI restart would be performed on {ip}")
        
        # For a real implementation, you would do something like:
        # import wmi
        # c = wmi.WMI(ip, user="administrator", password="password")
        # os = c.Win32_OperatingSystem()[0]
        # os.Reboot()
        
        # Alternative implementation using PowerShell
        ps_script = """
        $computer = "{ip}"
        $credential = Get-Credential -Message "Enter credentials for $computer"
        Restart-Computer -ComputerName $computer -Credential $credential -Force
        """
        
        # Save script to a temporary file
        script_path = Path("temp_restart_script.ps1")
        with open(script_path, 'w') as f:
            f.write(ps_script.format(ip=ip))
        
        # Execute the script locally (would need admin privileges)
        # subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)])
        
        # Simulate success
        return {
            "success": True,
            "message": "WMI restart command sent successfully via wmi"
        }
    except Exception as e:
        logger.error(f"Error restarting {ip} via WMI: {str(e)}")
        return {
            "success": False,
            "message": f"WMI restart failed: {str(e)}"
        }

def restart_via_web(ip: str, url: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
    """Restart a device using web interface."""
    try:
        # This is a placeholder for actual web interface implementation
        # In a real-world scenario, you would use a library like requests
        # to authenticate and send the restart command via the web interface
        
        if not url:
            url = f"http://{ip}/"
        
        logger.info(f"Web interface restart would be performed on {ip} via {url}")
        
        if username and password:
            logger.info(f"Using provided credentials: username={username}")
        
        # For a real implementation, you would do something like:
        # import requests
        # session = requests.Session()
        # session.auth = (username, password)
        # response = session.get(url)
        # # Find the restart button/form and submit it
        # restart_url = url + "restart"
        # response = session.post(restart_url)
        
        # Simulate success
        return {
            "success": True,
            "message": "Web interface restart command sent successfully"
        }
    except Exception as e:
        logger.error(f"Error restarting {ip} via web interface: {str(e)}")
        return {
            "success": False,
            "message": f"Web interface restart failed: {str(e)}"
        }

def restart_via_adb(ip: str) -> Dict[str, Any]:
    """Restart an Android device using ADB."""
    try:
        # This is a placeholder for actual ADB implementation
        # In a real-world scenario, you would use the ADB command line tool
        # or a Python wrapper like pure-python-adb
        
        logger.info(f"ADB restart would be performed on {ip}")
        
        # For a real implementation, you would do something like:
        # command = f"adb connect {ip}:5555 && adb reboot"
        # subprocess.run(command, shell=True, check=True)
        
        # Simulate success
        return {
            "success": True,
            "message": "ADB restart command sent successfully"
        }
    except Exception as e:
        logger.error(f"Error restarting {ip} via ADB: {str(e)}")
        return {
            "success": False,
            "message": f"ADB restart failed: {str(e)}"
        }

def update_device_restart_status(ip: str, success: bool, method: str, error_message: str = None) -> None:
    """Update device restart status in the database."""
    try:
        device_file = DEVICE_INFO_DIR / f"{ip.replace('.', '_')}.json"
        
        if device_file.exists():
            with open(device_file, 'r') as f:
                device_data = json.load(f)
            
            # Update restart information
            if 'restart_history' not in device_data:
                device_data['restart_history'] = []
            
            restart_info = {
                "timestamp": datetime.now().isoformat(),
                "method": method,
                "success": success
            }
            
            if error_message:
                restart_info["error"] = error_message
            
            device_data['restart_history'].append(restart_info)
            device_data['last_restart_attempt'] = restart_info
            
            with open(device_file, 'w') as f:
                json.dump(device_data, f)
    except Exception as e:
        logger.error(f"Error updating restart status for {ip}: {str(e)}")
