import socket
import json
import logging
import concurrent.futures
import datetime
from pathlib import Path
from typing import Dict, List, Any, Union

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
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443
]

# Service names for common ports
PORT_SERVICES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAP-SSL",
    995: "POP3-SSL",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

# Ensure directory exists
PORTS_DIR.mkdir(parents=True, exist_ok=True)

def scan_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Scan a single port on a given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            service = PORT_SERVICES.get(port, "unknown")
            return {
                "port": port,
                "status": "open",
                "service": service
            }
        else:
            return {
                "port": port,
                "status": "closed"
            }
    except Exception as e:
        logger.error(f"Error scanning port {port} on {ip}: {str(e)}")
        return {
            "port": port,
            "status": "error",
            "error": str(e)
        }

def scan_ports(ip: str, ports: List[int] = None, timeout: float = 1.0, max_workers: int = 50) -> Dict[str, Any]:
    """Scan multiple ports on a given IP address."""
    if ports is None:
        ports = COMMON_PORTS
    
    try:
        logger.info(f"Starting port scan for {ip} on {len(ports)} ports")
        
        open_ports = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create a dictionary of futures to port numbers
            future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result["status"] == "open":
                        open_ports.append(result)
                except Exception as e:
                    logger.error(f"Error processing result for port {port}: {str(e)}")
        
        # Save results to file
        save_port_results(ip, open_ports)
        
        logger.info(f"Port scan completed for {ip}. Found {len(open_ports)} open ports.")
        
        return {
            "status": "success",
            "ip": ip,
            "open_ports": open_ports,
            "total_scanned": len(ports)
        }
    
    except Exception as e:
        logger.error(f"Error scanning ports for {ip}: {str(e)}")
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