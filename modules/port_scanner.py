import socket
import json
import logging
import concurrent.futures
import datetime
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Union
import re
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("port_scanner")

# Constants
PORTS_DIR = Path("data/ports")
PROGRESS_DIR = Path("data/scan_progress")
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443
]

# Service names for common ports with descriptions
PORT_SERVICES = {
    20: {"name": "FTP-data", "description": "File Transfer Protocol (Data Channel)"},
    21: {"name": "FTP", "description": "File Transfer Protocol (Control Channel)"},
    22: {"name": "SSH", "description": "Secure Shell"},
    23: {"name": "Telnet", "description": "Telnet Protocol (Unencrypted)"},
    25: {"name": "SMTP", "description": "Simple Mail Transfer Protocol"},
    53: {"name": "DNS", "description": "Domain Name System"},
    80: {"name": "HTTP", "description": "Hypertext Transfer Protocol"},
    110: {"name": "POP3", "description": "Post Office Protocol v3"},
    123: {"name": "NTP", "description": "Network Time Protocol"},
    143: {"name": "IMAP", "description": "Internet Message Access Protocol"},
    443: {"name": "HTTPS", "description": "HTTP Secure"},
    445: {"name": "SMB", "description": "Server Message Block"},
    993: {"name": "IMAP-SSL", "description": "IMAP over SSL"},
    995: {"name": "POP3-SSL", "description": "POP3 over SSL"},
    1433: {"name": "MSSQL", "description": "Microsoft SQL Server"},
    1521: {"name": "Oracle", "description": "Oracle Database"},
    3306: {"name": "MySQL", "description": "MySQL Database"},
    3389: {"name": "RDP", "description": "Remote Desktop Protocol"},
    5432: {"name": "PostgreSQL", "description": "PostgreSQL Database"},
    5900: {"name": "VNC", "description": "Virtual Network Computing"},
    8080: {"name": "HTTP-Proxy", "description": "HTTP Proxy/Alternate Port"},
    8443: {"name": "HTTPS-Alt", "description": "HTTPS Alternate Port"}
}

# Security risk levels for common services
SECURITY_RISK = {
    "FTP": "Medium",
    "Telnet": "High",
    "SMTP": "Low",
    "HTTP": "Low",
    "RDP": "Medium",
    "VNC": "Medium",
    "MySQL": "Medium",
    "MSSQL": "Medium",
    "Oracle": "Medium",
    "PostgreSQL": "Medium"
}

# Ensure directories exist
PORTS_DIR.mkdir(parents=True, exist_ok=True)
PROGRESS_DIR.mkdir(parents=True, exist_ok=True)

# Thread-safe storage for scan progress
scan_progress = {}
progress_lock = threading.Lock()

def validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_service_name(ip: str, port: int, timeout: float = 1.0) -> Dict[str, str]:
    """Attempt to identify the service running on a port by grabbing the banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send a simple HTTP GET request for HTTP-like services
        if port in [80, 443, 8080, 8443]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        else:
            sock.send(b"\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        service_info = {"name": "unknown", "description": "", "banner": "", "risk": ""}
        
        if banner:
            # Store the banner (truncated if too long)
            if len(banner) > 100:
                service_info["banner"] = banner[:100] + "..."
            else:
                service_info["banner"] = banner
                
            # Try to identify service from banner
            if "HTTP" in banner:
                service_name = "HTTP" if port in [80, 8080] else "HTTPS"
                service_info["name"] = service_name
                service_info["description"] = "Web Server"
                service_info["risk"] = SECURITY_RISK.get(service_name, "Low")
            elif "SSH" in banner:
                service_info["name"] = "SSH"
                service_info["description"] = "Secure Shell"
                service_info["risk"] = "Low"
            elif "FTP" in banner:
                service_info["name"] = "FTP"
                service_info["description"] = "File Transfer Protocol"
                service_info["risk"] = SECURITY_RISK.get("FTP", "Medium")
            elif "SMTP" in banner:
                service_info["name"] = "SMTP"
                service_info["description"] = "Mail Server"
                service_info["risk"] = SECURITY_RISK.get("SMTP", "Low")
            elif "MySQL" in banner:
                service_info["name"] = "MySQL"
                service_info["description"] = "MySQL Database"
                service_info["risk"] = SECURITY_RISK.get("MySQL", "Medium")
            elif "POP3" in banner:
                service_info["name"] = "POP3"
                service_info["description"] = "Mail Access Protocol"
                service_info["risk"] = "Low"
            else:
                # Return the first line of the banner if we can't identify it
                first_line = banner.split('\n')[0]
                if len(first_line) > 20:
                    first_line = first_line[:20] + "..."
                service_info["name"] = first_line
                service_info["description"] = "Unknown Service"
        
        # If we couldn't identify from banner, try socket service name
        if service_info["name"] == "unknown":
            try:
                service = socket.getservbyport(port)
                service_info["name"] = service.upper()
                
                # Check if it's in our known services
                if port in PORT_SERVICES:
                    service_info["description"] = PORT_SERVICES[port]["description"]
                    service_info["risk"] = SECURITY_RISK.get(PORT_SERVICES[port]["name"], "")
            except:
                # Fall back to our predefined list
                if port in PORT_SERVICES:
                    service_info["name"] = PORT_SERVICES[port]["name"]
                    service_info["description"] = PORT_SERVICES[port]["description"]
                    service_info["risk"] = SECURITY_RISK.get(PORT_SERVICES[port]["name"], "")
        
        return service_info
    except Exception as e:
        logger.debug(f"Error grabbing banner for {ip}:{port}: {str(e)}")
        
        # Fall back to our predefined list
        if port in PORT_SERVICES:
            return {
                "name": PORT_SERVICES[port]["name"],
                "description": PORT_SERVICES[port]["description"],
                "banner": "",
                "risk": SECURITY_RISK.get(PORT_SERVICES[port]["name"], "")
            }
        
        return {"name": "unknown", "description": "", "banner": "", "risk": ""}

def scan_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Scan a single port on a given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            service_info = get_service_name(ip, port, timeout)
            return {
                "port": port,
                "state": "open",
                "service": service_info["name"],
                "description": service_info["description"],
                "banner": service_info["banner"],
                "risk": service_info["risk"]
            }
        else:
            return {
                "port": port,
                "state": "closed"
            }
    except socket.timeout:
        return {
            "port": port,
            "state": "filtered"
        }
    except Exception as e:
        logger.error(f"Error scanning port {port} on {ip}: {str(e)}")
        return {
            "port": port,
            "state": "error",
            "error": str(e)
        }

def update_progress(ip: str, total_ports: int, scanned_ports: int, open_ports: List[Dict[str, Any]], current_port: int, status: str = "in_progress") -> None:
    """Update the scan progress for a given IP."""
    with progress_lock:
        progress = (scanned_ports / total_ports * 100) if total_ports > 0 else 0
        scan_progress[ip] = {
            "status": status,
            "progress": round(progress, 2),
            "total_ports": total_ports,
            "scanned_ports": scanned_ports,
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "current_port": current_port,
            "timestamp": str(datetime.datetime.now())
        }
        
        # Save to file for persistence
        progress_file = PROGRESS_DIR / f"{ip.replace('.', '_')}.json"
        with open(progress_file, 'w') as f:
            json.dump(scan_progress[ip], f)

def scan_ports(ip: str, port_range: List[int] = None, timeout: float = 1.0, max_threads: int = 50) -> Dict[str, Any]:
    """Scan multiple ports on a given IP address in a separate thread."""
    if port_range is None:
        port_range = COMMON_PORTS
    
    if not validate_ip(ip):
        return {
            "status": "error",
            "message": "Invalid IP address"
        }
    
    if not port_range:
        return {
            "status": "error",
            "message": "No ports specified to scan"
        }
    
    try:
        logger.info(f"Starting port scan for {ip} on {len(port_range)} ports")
        
        # Initialize progress
        open_ports = []
        total_ports = len(port_range)
        scanned_ports = 0
        
        with progress_lock:
            if ip in scan_progress and scan_progress[ip]["status"] == "in_progress":
                return {
                    "status": "error",
                    "message": "Scan already in progress for this IP"
                }
        
        update_progress(ip, total_ports, scanned_ports, open_ports, port_range[0], "in_progress")
        
        # Start scanning in a separate thread
        def perform_scan():
            nonlocal scanned_ports, open_ports
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in port_range}
                    
                    for future in concurrent.futures.as_completed(future_to_port):
                        port = future_to_port[future]
                        try:
                            result = future.result()
                            scanned_ports += 1
                            if result["state"] == "open":
                                open_ports.append(result)
                            update_progress(ip, total_ports, scanned_ports, open_ports, port)
                        except Exception as e:
                            logger.error(f"Error processing result for port {port}: {str(e)}")
                            scanned_ports += 1
                            update_progress(ip, total_ports, scanned_ports, open_ports, port)
            
                # Scan completed
                save_port_results(ip, open_ports)
                update_progress(ip, total_ports, scanned_ports, open_ports, port_range[-1], "completed")
                logger.info(f"Port scan completed for {ip}. Found {len(open_ports)} open ports.")
            except Exception as e:
                logger.error(f"Error during port scan for {ip}: {str(e)}")
                update_progress(ip, total_ports, scanned_ports, open_ports, port if 'port' in locals() else port_range[0], "error")
        
        scan_thread = threading.Thread(target=perform_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        return {
            "status": "started",
            "ip": ip,
            "message": f"Port scan started for {ip} on {total_ports} ports"
        }
    
    except Exception as e:
        logger.error(f"Error initiating port scan for {ip}: {str(e)}")
        update_progress(ip, len(port_range), 0, [], port_range[0], "error")
        return {
            "status": "error",
            "message": f"Failed to scan ports: {str(e)}"
        }

def save_port_results(ip: str, open_ports: List[Dict[str, Any]]) -> None:
    """Save port scan results to a file."""
    try:
        port_file = PORTS_DIR / f"{ip.replace('.', '_')}.json"
        
        port_data = {
            "ip": ip,
            "timestamp": str(datetime.datetime.now()),
            "open_ports": open_ports
        }
        
        with open(port_file, 'w') as f:
            json.dump(port_data, f)
        
        logger.info(f"Port scan results saved for {ip}")
    
    except Exception as e:
        logger.error(f"Error saving port scan results for {ip}: {str(e)}")

def get_port_results(ip: str) -> Dict[str, Any]:
    """Get saved port scan results for a given IP address."""
    try:
        port_file = PORTS_DIR / f"{ip.replace('.', '_')}.json"
        
        if not port_file.exists():
            return {
                "status": "no_data",
                "message": "No port scan data available"
            }
        
        with open(port_file, 'r') as f:
            port_data = json.load(f)
        
        return {
            "status": "success",
            "ip": ip,
            "open_ports": port_data.get("open_ports", []),
            "timestamp": port_data.get("timestamp")
        }
    
    except Exception as e:
        logger.error(f"Error getting port scan results for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to get port scan results: {str(e)}"
        }

def get_scan_status(ip: str) -> Dict[str, Any]:
    """Get the current status of a port scan for a given IP."""
    try:
        with progress_lock:
            if ip not in scan_progress:
                progress_file = PROGRESS_DIR / f"{ip.replace('.', '_')}.json"
                if progress_file.exists():
                    with open(progress_file, 'r') as f:
                        scan_progress[ip] = json.load(f)
                else:
                    return {
                        "status": "no_data",
                        "message": "No scan in progress or completed for this IP"
                    }
            
            status_data = scan_progress[ip].copy()
            
            if status_data["status"] == "completed":
                # Clean up progress data
                progress_file = PROGRESS_DIR / f"{ip.replace('.', '_')}.json"
                if progress_file.exists():
                    progress_file.unlink()
                with progress_lock:
                    scan_progress.pop(ip, None)
                
                # Return final results
                return get_port_results(ip)
            
            return status_data
    
    except Exception as e:
        logger.error(f"Error getting scan status for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to get scan status: {str(e)}"
        }

def cancel_scan(ip: str) -> Dict[str, Any]:
    """Cancel an ongoing port scan for a given IP."""
    try:
        with progress_lock:
            if ip not in scan_progress or scan_progress[ip]["status"] != "in_progress":
                return {
                    "status": "error",
                    "message": "No scan in progress for this IP"
                }
            
            # Mark as cancelled
            scan_progress[ip]["status"] = "cancelled"
            
            # Save to file
            progress_file = PROGRESS_DIR / f"{ip.replace('.', '_')}.json"
            with open(progress_file, 'w') as f:
                json.dump(scan_progress[ip], f)
            
            return {
                "status": "success",
                "message": f"Scan for {ip} has been cancelled"
            }
    
    except Exception as e:
        logger.error(f"Error cancelling scan for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to cancel scan: {str(e)}"
        }

def test_connection(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Test connection to a specific IP and port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            service_info = get_service_name(ip, port, timeout)
            return {
                "status": "success",
                "message": f"Connection to {ip}:{port} successful",
                "service": service_info["name"],
                "description": service_info["description"],
                "banner": service_info["banner"],
                "risk": service_info["risk"]
            }
        else:
            return {
                "status": "error",
                "message": f"Connection to {ip}:{port} failed"
            }
    except Exception as e:
        logger.error(f"Error testing connection to {ip}:{port}: {str(e)}")
        return {
            "status": "error",
            "message": f"Error testing connection: {str(e)}"
        }

def auto_detect_ports(ip: str, timeout: float = 0.5) -> Dict[str, Any]:
    """Auto-detect common open ports on a given IP."""
    try:
        if not validate_ip(ip):
            return {
                "status": "error",
                "message": "Invalid IP address"
            }
        
        # Test connection to the IP first
        test_port = 80  # Use HTTP as a test
        test_result = test_connection(ip, test_port, timeout)
        
        if test_result["status"] == "error":
            # Try another common port
            test_port = 443  # Try HTTPS
            test_result = test_connection(ip, test_port, timeout)
            
            if test_result["status"] == "error":
                # One more try with SSH
                test_port = 22
                test_result = test_connection(ip, test_port, timeout)
                
                if test_result["status"] == "error":
                    return {
                        "status": "error",
                        "message": "Could not connect to the target IP"
                    }
        
        # Quick scan of the most common ports
        quick_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        for port in quick_ports:
            result = scan_port(ip, port, timeout)
            if result["state"] == "open":
                open_ports.append(result)
        
        return {
            "status": "success",
            "ip": ip,
            "open_ports": open_ports,
            "message": f"Found {len(open_ports)} open ports in quick scan"
        }
    
    except Exception as e:
        logger.error(f"Error auto-detecting ports for {ip}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to auto-detect ports: {str(e)}"
        }

def get_scan_history() -> Dict[str, Any]:
    """Get history of all completed port scans."""
    try:
        history = []
        
        # Get all port scan result files
        port_files = list(PORTS_DIR.glob('*.json'))
        
        for file in port_files:
            try:
                with open(file, 'r') as f:
                    port_data = json.load(f)
                
                ip = port_data.get("ip", "unknown")
                timestamp = port_data.get("timestamp", "")
                open_ports = port_data.get("open_ports", [])
                
                history.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "open_ports_count": len(open_ports)
                })
            except Exception as e:
                logger.error(f"Error reading port scan file {file}: {str(e)}")
        
        # Sort by timestamp (newest first)
        history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return {
            "status": "success",
            "history": history
        }
    
    except Exception as e:
        logger.error(f"Error getting scan history: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to get scan history: {str(e)}"
        }
