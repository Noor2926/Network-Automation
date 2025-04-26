import socket
import ipaddress
import threading

import time
import json
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Any, Union
import concurrent.futures
import subprocess
import re
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("scan")

# Constants
SCAN_HISTORY_DIR = Path("data/scan_history")
DEVICES_DIR = Path("data/devices")

# Ensure directories exist
SCAN_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
DEVICES_DIR.mkdir(parents=True, exist_ok=True)

# Global variables for scan status
scan_status = {
    "status": "idle",
    "progress": 0,
    "current_ip": None,
    "results": [],
    "total_ips": 0,
    "start_time": None,
    "end_time": None
}

# Lock for thread safety
status_lock = threading.Lock()

def parse_ip_range(ip_range: str) -> List[str]:
    """Parse IP range string into a list of IP addresses."""
    try:
        # Check if it's a CIDR notation (e.g., 192.168.1.0/24)
        if '/' in ip_range:
            return [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
        
        # Check if it's a range notation (e.g., 192.168.1.1-192.168.1.254)
        elif '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            
            # If the end IP is just a number, assume it's the last octet
            if '.' not in end_ip:
                start_parts = start_ip.split('.')
                end_ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{end_ip}"
            
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]
        
        # Single IP address
        else:
            return [ip_range]
    
    except Exception as e:
        logger.error(f"Error parsing IP range {ip_range}: {str(e)}")
        return []

def get_mac_address(ip: str) -> str:
    """
    Get MAC address for an IP address.
    This is a platform-dependent function and may not work on all systems.
    """
    try:
        import subprocess
        import re
        import platform
        
        system = platform.system().lower()
        
        if system == 'windows':
            # Use ARP on Windows
            output = subprocess.check_output(f'arp -a {ip}', shell=True).decode('utf-8')
            mac_matches = re.findall(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
            if mac_matches:
                return mac_matches[0]
        elif system == 'linux' or system == 'darwin':
            # Use ARP on Linux/Mac
            output = subprocess.check_output(f'arp -n {ip}', shell=True).decode('utf-8')
            mac_matches = re.findall(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', output)
            if mac_matches:
                return mac_matches[0]
    except:
        pass
    
    return ""

def get_vendor_from_mac(mac: str) -> str:
    """
    Get vendor information from MAC address.
    This is a simplified version that would need to be expanded with a proper OUI database.
    """
    # In a real implementation, you would use a MAC address OUI database
    # For now, return empty string
    return ""

def scan_ip(ip: str, timeout: float = 1.0) -> Dict[str, Any]:
    """Scan a single IP address with improved hostname resolution."""
    try:
        # Update current IP in scan status
        with status_lock:
            scan_status["current_ip"] = ip
        
        # Try to resolve hostname with increased timeout for better results
        hostname = ""
        try:
            # Set a shorter socket timeout for hostname resolution
            socket.setdefaulttimeout(2.0)  # 2 seconds for hostname resolution
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            # If standard hostname resolution fails, try alternative methods
            try:
                # On Windows, try using nbtstat for NetBIOS names
                if platform.system().lower() == 'windows':
                    try:
                        output = subprocess.check_output(f'nbtstat -A {ip}', shell=True, timeout=2).decode('utf-8', errors='ignore')
                        name_match = re.search(r'<00>\s+UNIQUE\s+(\S+)', output)
                        if name_match:
                            hostname = name_match.group(1).strip()
                    except:
                        pass
                # On Linux, try using nmblookup
                elif platform.system().lower() == 'linux':
                    try:
                        output = subprocess.check_output(f'nmblookup -A {ip}', shell=True, timeout=2).decode('utf-8', errors='ignore')
                        name_match = re.search(r'<00>\s+(\S+)', output)
                        if name_match:
                            hostname = name_match.group(1).strip()
                    except:
                        pass
            except:
                pass
            finally:
                # Reset default timeout
                socket.setdefaulttimeout(None)
        
        # Try to connect to common ports to determine if device is active
        is_active = False
        open_ports = []
        for port in [80, 443, 22, 445, 139, 135, 3389, 8080]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    is_active = True
                    open_ports.append(port)
            except:
                pass
        
        # If no ports are open, try a simple ping (socket connection to port 7)
        if not is_active:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, 7))
                sock.close()
                
                if result == 0:
                    is_active = True
                    open_ports.append(7)
            except:
                pass
        
        # If still not active, try ICMP ping as a last resort
        if not is_active:
            try:
                from modules.ping import ping_host
                ping_result = ping_host(ip, count=1, timeout=timeout)
                is_active = ping_result.get("success", False)
            except:
                pass
        
        # Try to get MAC address
        mac = get_mac_address(ip)
        vendor = get_vendor_from_mac(mac) if mac else ""
        
        # Create device info
        device_info = {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "status": "Active" if is_active else "Inactive",
            "last_seen": str(datetime.datetime.now()),
            "open_ports": open_ports
        }
        
        # Save device info to file only if active or has hostname/MAC
        if is_active or hostname or mac:
            save_device_info(device_info)
        
        return device_info
    
    except Exception as e:
        logger.error(f"Error scanning IP {ip}: {str(e)}")
        return {
            "ip": ip,
            "error": str(e)
        }

def save_device_info(device_info: Dict[str, Any]) -> None:
    """Save device information to a file."""
    try:
        ip = device_info["ip"]
        device_file = DEVICES_DIR / f"{ip.replace('.', '_')}.json"
        
        with open(device_file, 'w') as f:
            json.dump(device_info, f)
    
    except Exception as e:
        logger.error(f"Error saving device info: {str(e)}")

def save_scan_history(ip_range: str, results: List[Dict[str, Any]], start_time: float, end_time: float) -> None:
    """Save scan history to a file."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        history_file = SCAN_HISTORY_DIR / f"scan_{timestamp}.json"
        
        history_data = {
            "timestamp": str(datetime.datetime.now()),
            "ip_range": ip_range,
            "devices_found": len(results),
            "duration_seconds": end_time - start_time,
            "results": results
        }
        
        with open(history_file, 'w') as f:
            json.dump(history_data, f)
        
        logger.info(f"Scan history saved to {history_file}")
    
    except Exception as e:
        logger.error(f"Error saving scan history: {str(e)}")

def scan_network(ip_range: str, timeout: float = 1.0, max_threads: int = 100) -> None:
    """Scan a network range in a separate thread."""
    # Start scan in a separate thread
    scan_thread = threading.Thread(target=_scan_network_thread, args=(ip_range, timeout, max_threads))
    scan_thread.daemon = True
    scan_thread.start()

def _scan_network_thread(ip_range: str, timeout: float = 1.0, max_threads: int = 100) -> None:
    """Thread function to scan a network range."""
    try:
        # Parse IP range
        ip_list = parse_ip_range(ip_range)
        total_ips = len(ip_list)
        
        if total_ips == 0:
            logger.error(f"No valid IP addresses in range: {ip_range}")
            return
        
        # Initialize scan status
        with status_lock:
            scan_status["status"] = "in_progress"
            scan_status["progress"] = 0
            scan_status["current_ip"] = None
            scan_status["results"] = []
            scan_status["total_ips"] = total_ips
            scan_status["start_time"] = time.time()
            scan_status["end_time"] = None
        
        logger.info(f"Starting scan of {total_ips} IP addresses in range {ip_range}")
        
        # Create a thread pool
        results = []
        scanned_count = 0
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all scan tasks
            future_to_ip = {executor.submit(scan_ip, ip, timeout): ip for ip in ip_list}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if "error" not in result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error processing result for IP {ip}: {str(e)}")
                
                # Update progress
                scanned_count += 1
                with status_lock:
                    scan_status["progress"] = int((scanned_count / total_ips) * 100)
                    scan_status["results"] = results
        
        # Scan completed
        end_time = time.time()
        
        # Update scan status
        with status_lock:
            scan_status["status"] = "idle"
            scan_status["progress"] = 100
            scan_status["current_ip"] = None
            scan_status["results"] = results
            scan_status["end_time"] = end_time
        
        # Save scan history
        save_scan_history(ip_range, results, scan_status["start_time"], end_time)
        
        logger.info(f"Scan completed. Found {len(results)} devices.")
    
    except Exception as e:
        logger.error(f"Error scanning network: {str(e)}")
        
        # Update scan status on error
        with status_lock:
            scan_status["status"] = "error"
            scan_status["end_time"] = time.time()

def get_scan_status() -> Dict[str, Any]:
    """Get the current scan status."""
    with status_lock:
        return scan_status.copy()

def get_all_devices() -> List[Dict[str, Any]]:
    """Get all devices from the device directory."""
    devices = []
    try:
        device_files = list(DEVICES_DIR.glob('*.json'))
        
        for file in device_files:
            try:
                with open(file, 'r') as f:
                    device_data = json.load(f)
                    devices.append(device_data)
            except Exception as e:
                logger.error(f"Error reading device file {file}: {str(e)}")
    except Exception as e:
        logger.error(f"Error getting devices: {str(e)}")
    
    return devices
