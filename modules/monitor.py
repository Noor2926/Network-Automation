import psutil
import time
import socket
import datetime
import threading
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from collections import deque

try:
    from ping3 import ping
except ImportError:
    logging.warning("ping3 module not available, latency monitoring will be disabled")
    ping = None

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("monitor")

# Constants
MAX_HISTORY_POINTS = 60  # Store 60 data points (2 minutes at 2-second intervals)
MONITOR_DATA_FILE = Path("data/monitor_data.json")
MONITOR_INTERVAL = 2  # Monitoring interval in seconds

# Ensure data directory exists
MONITOR_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

# Global variables
monitoring_thread = None
is_monitoring = False
bandwidth_history = deque(maxlen=MAX_HISTORY_POINTS)
latency_history = deque(maxlen=MAX_HISTORY_POINTS)
connected_hosts = []
network_info = {}
interfaces = []
prev_bytes_sent = 0
prev_bytes_recv = 0
prev_time = 0
status_lock = threading.Lock()

def get_network_info() -> Dict[str, str]:
    """Get basic network information like hostname and IP address."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # Extract network range from local IP (assuming /24 subnet)
        ip_parts = ip_address.split('.')
        network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
        
        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "network_range": network_range,
            "gateway": gateway,
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error getting network info: {str(e)}")
        return {
            "hostname": "Unknown",
            "ip_address": "Unknown",
            "network_range": "Unknown",
            "gateway": "Unknown",
            "status": "error",
            "message": str(e)
        }

def get_network_interfaces() -> List[Dict[str, Any]]:
    """Get details of all network interfaces."""
    try:
        interfaces = []
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addrs in net_if_addrs.items():
            if interface_name.startswith('lo'):
                continue
                
            if interface_name in net_if_stats and net_if_stats[interface_name].isup:
                interface_info = {
                    "name": interface_name,
                    "addresses": [],
                    "dns_servers": get_dns_servers(),
                    "status": "up"
                }
                
                for addr in addrs:
                    addr_info = {
                        "address": addr.address,
                        "netmask": getattr(addr, 'netmask', None),
                        "broadcast": getattr(addr, 'broadcast', None),
                        "type": (
                            "IPv4" if addr.family == socket.AF_INET else
                            "IPv6" if addr.family == socket.AF_INET6 else
                            "MAC" if addr.family == psutil.AF_LINK else "Unknown"
                        )
                    }
                    interface_info["addresses"].append(addr_info)
                
                interfaces.append(interface_info)
        
        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {str(e)}")
        return [{"name": "Unknown", "status": "error", "message": str(e)}]

def get_dns_servers() -> List[str]:
    """Get DNS servers from the system."""
    dns_servers = []
    try:
        if hasattr(psutil, 'WINDOWS') and psutil.WINDOWS:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ) as key:
                dns = winreg.QueryValueEx(key, 'NameServer')[0]
                if dns:
                    dns_servers = dns.split(',')
        else:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            except FileNotFoundError:
                pass
        
        return dns_servers or ["8.8.8.8", "8.8.4.4"]  # Default to Google DNS
    except Exception as e:
        logger.error(f"Error getting DNS servers: {str(e)}")
        return ["8.8.8.8", "8.8.4.4"]

def get_bandwidth_usage() -> tuple:
    """Get current bytes sent and received."""
    try:
        net_io = psutil.net_io_counters()
        return net_io.bytes_sent, net_io.bytes_recv
    except Exception as e:
        logger.error(f"Error getting bandwidth usage: {str(e)}")
        return 0, 0

def measure_latency(host: str = "8.8.8.8"):
    """Measure ping latency to a host (default: Google's DNS)."""
    try:
        if ping is None:
            return None
            
        latency = ping(host, unit="ms")
        return round(latency, 2) if latency is not None else None
    except Exception as e:
        logger.error(f"Error measuring latency to {host}: {str(e)}")
        return None

def scan_network(subnet: str = None) -> List[Dict[str, str]]:
    """Scan the network for connected hosts using ARP."""
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available, network scanning disabled")
        return []
        
    if not subnet:
        network_info = get_network_info()
        subnet = network_info.get("network_range", "192.168.1.0/24")
        
    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        return [{"ip": received.psrc, "mac": received.hwsrc} for sent, received in result]
    except PermissionError:
        logger.error("Permission error during network scan - run as administrator")
        return []
    except Exception as e:
        logger.error(f"Error during network scan: {str(e)}")
        return []

def get_system_resources() -> Dict[str, Any]:
    """Get system resource usage (CPU, memory, disk)."""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "cpu_percent": cpu_percent,
            "memory": {
                "total": memory.total,
                "used": memory.used,
                "free": memory.free,
                "percent": memory.percent
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            },
            "status": "success"
        }
    except Exception as e:
        logger.error(f"Error getting system resources: {str(e)}")
        return {"status": "error", "message": str(e)}

def monitor_network() -> None:
    """Monitor network metrics and update global variables."""
    global prev_bytes_sent, prev_bytes_recv, prev_time, is_monitoring
    
    with status_lock:
        if is_monitoring:
            return
    
    is_monitoring = True
    logger.info("Starting network monitoring")
    
    try:
        while is_monitoring:
            current_time = time.time()
            
            # Get bandwidth usage
            bytes_sent, bytes_recv = get_bandwidth_usage()
            
            # Calculate rates if we have previous data
            if prev_time != 0:
                elapsed = current_time - prev_time
                sent_rate = (bytes_sent - prev_bytes_sent) / elapsed
                recv_rate = (bytes_recv - prev_bytes_recv) / elapsed
                
                bandwidth_history.append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "sent_bps": sent_rate,
                    "recv_bps": recv_rate
                })
            
            prev_bytes_sent, prev_bytes_recv = bytes_sent, bytes_recv
            prev_time = current_time
            
            # Measure latency
            latency = measure_latency()
            if latency is not None:
                latency_history.append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "latency_ms": latency
                })
            
            # Scan network periodically (every 30 seconds)
            if int(current_time) % 30 == 0:
                with status_lock:
                    connected_hosts.clear()
                    connected_hosts.extend(scan_network())
            
            # Save data periodically (every 10 seconds)
            if int(current_time) % 10 == 0:
                save_monitor_data()
            
            time.sleep(MONITOR_INTERVAL)
            
    except Exception as e:
        logger.error(f"Error in network monitoring: {str(e)}")
    finally:
        with status_lock:
            is_monitoring = False
        save_monitor_data()
        logger.info("Network monitoring stopped")

def start_monitoring() -> Dict[str, str]:
    """Start network monitoring in a separate thread."""
    global monitoring_thread, is_monitoring
    
    with status_lock:
        if is_monitoring:
            return {"status": "error", "message": "Monitoring already running"}
        
        monitoring_thread = threading.Thread(target=monitor_network, daemon=True)
        monitoring_thread.start()
        return {"status": "success", "message": "Monitoring started"}

def stop_monitoring() -> Dict[str, str]:
    """Stop network monitoring."""
    global is_monitoring, monitoring_thread
    
    with status_lock:
        if not is_monitoring:
            return {"status": "error", "message": "Monitoring not running"}
        
        is_monitoring = False
    
    if monitoring_thread:
        monitoring_thread.join(timeout=5.0)
        monitoring_thread = None
    
    save_monitor_data()
    return {"status": "success", "message": "Monitoring stopped"}

def save_monitor_data() -> None:
    """Save monitoring data to file."""
    try:
        data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "network_info": get_network_info(),
            "interfaces": get_network_interfaces(),
            "bandwidth_history": list(bandwidth_history),
            "latency_history": list(latency_history),
            "connected_hosts": connected_hosts,
            "system_resources": get_system_resources()
        }
        
        with MONITOR_DATA_FILE.open('w') as f:
            json.dump(data, f, indent=2)
        
        logger.debug("Monitoring data saved")
    except Exception as e:
        logger.error(f"Error saving monitor data: {str(e)}")

def get_monitor_data() -> Dict[str, Any]:
    """Get current monitoring data."""
    try:
        with status_lock:
            data = {
                "is_monitoring": is_monitoring,
                "network_info": get_network_info(),
                "interfaces": get_network_interfaces(),
                "bandwidth_history": list(bandwidth_history),
                "latency_history": list(latency_history),
                "connected_hosts": connected_hosts,
                "system_resources": get_system_resources(),
                "status": "success"
            }
        
        return data
    except Exception as e:
        logger.error(f"Error getting monitor data: {str(e)}")
        return {"status": "error", "message": str(e)}
