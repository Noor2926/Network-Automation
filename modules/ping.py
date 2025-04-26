import subprocess
import platform
import socket
import time
import logging
from typing import Dict, Any, List


# Configure logging
logger = logging.getLogger("ping")

def ping_host(ip: str, count: int = 4, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Ping a host and return the results.
    
    Args:
        ip: IP address to ping
        count: Number of ping packets to send
        timeout: Timeout in seconds for each ping
    
    Returns:
        Dictionary with ping results
    """
    try:
        # Determine the ping command based on the operating system
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        # Convert timeout to milliseconds for Windows
        timeout_value = int(timeout * 1000) if platform.system().lower() == 'windows' else int(timeout)
        
        # Build the command
        command = ['ping', param, str(count), timeout_param, str(timeout_value), ip]
        
        # Execute the ping command
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout * count + 5)
        
        # Parse the output
        output = result.stdout
        
        # Check if ping was successful
        if result.returncode == 0:
            return {
                "success": True,
                "ip": ip,
                "output": output,
                "packets_sent": count,
                "packets_received": count  # This is an approximation, would need to parse output for exact count
            }
        else:
            return {
                "success": False,
                "ip": ip,
                "output": output,
                "error": "Host unreachable",
                "packets_sent": count,
                "packets_received": 0
            }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "ip": ip,
            "error": "Ping command timed out",
            "output": "Ping command timed out after waiting for response."
        }
    except Exception as e:
        logger.error(f"Error pinging host {ip}: {str(e)}")
        return {
            "success": False,
            "ip": ip,
            "error": str(e),
            "output": f"Error executing ping: {str(e)}"
        }

def get_active_hosts(ip_range: str, timeout: float = 0.5) -> List[Dict[str, Any]]:
    """
    Get a list of active hosts in the specified IP range.
    
    Args:
        ip_range: IP range in CIDR notation (e.g., 192.168.1.0/24)
        timeout: Timeout in seconds for each ping
    
    Returns:
        List of dictionaries with active host information
    """
    from modules.scan import parse_ip_range
    
    active_hosts = []
    ip_list = parse_ip_range(ip_range)
    
    for ip in ip_list:
        try:
            # Try to connect to common ports to determine if device is active
            is_active = False
            for port in [80, 443, 22, 445]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        is_active = True
                        break
                except:
                    pass
            
            # If no ports are open, try a simple ping
            if not is_active:
                ping_result = ping_host(ip, count=1, timeout=timeout)
                is_active = ping_result["success"]
            
            # If active, try to get hostname
            hostname = ""
            if is_active:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                
                active_hosts.append({
                    "ip": ip,
                    "hostname": hostname,
                    "status": "Active"
                })
        
        except Exception as e:
            logger.error(f"Error checking host {ip}: {str(e)}")
    
    return active_hosts
