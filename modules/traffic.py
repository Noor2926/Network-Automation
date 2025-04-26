import time
import threading
import socket
import os
import json
import logging
from datetime import datetime
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("traffic")

# Try to import optional dependencies
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy is not available. Install with 'pip install scapy' for packet capture functionality.")

# Global variables for traffic monitoring
traffic_status = {
    "status": "idle",
    "start_time": None,
    "packets_captured": 0,
    "monitoring_interface": None,
    "capture_filter": "",
    "max_packets": 1000,
    "traffic_data": {
        "total_bytes": 0,
        "incoming_bytes": 0,
        "outgoing_bytes": 0,
        "protocols": {},
        "src_ips": defaultdict(int),
        "dst_ips": defaultdict(int),
        "connections": {},
        "packet_history": []
    }
}

# Keep track of active monitoring threads
active_monitors = {}
stop_capture = threading.Event()

def get_traffic_status():
    """Get current traffic monitoring status"""
    return traffic_status

def reset_traffic_data():
    """Reset traffic monitoring data"""
    global traffic_status
    
    traffic_status["packets_captured"] = 0
    traffic_status["traffic_data"] = {
        "total_bytes": 0,
        "incoming_bytes": 0,
        "outgoing_bytes": 0,
        "protocols": {},
        "src_ips": defaultdict(int),
        "dst_ips": defaultdict(int),
        "connections": {},
        "packet_history": []
    }

def packet_callback(packet):
    """Process captured packet and update traffic statistics"""
    global traffic_status
    
    if not SCAPY_AVAILABLE:
        return
    
    try:
        # Check if we should stop
        if stop_capture.is_set():
            return
        
        # Increment packet counter
        traffic_status["packets_captured"] += 1
        
        # Extract packet information
        timestamp = datetime.now()
        src_ip = "Unknown"
        dst_ip = "Unknown"
        src_port = None
        dst_port = None
        protocol = "Unknown"
        length = len(packet)
        info = ""
        
        # Update total bytes
        traffic_status["traffic_data"]["total_bytes"] += length
        
        # Extract IP information if available
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Determine if incoming or outgoing
            if is_local_ip(dst_ip):
                traffic_status["traffic_data"]["incoming_bytes"] += length
            elif is_local_ip(src_ip):
                traffic_status["traffic_data"]["outgoing_bytes"] += length
            
            # Update source and destination IP counts
            traffic_status["traffic_data"]["src_ips"][src_ip] += length
            traffic_status["traffic_data"]["dst_ips"][dst_ip] += length
            
            # Determine protocol and ports
            if packet.haslayer(scapy.TCP):
                base_protocol = "TCP"
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                flags = packet[scapy.TCP].flags
                
                # Format TCP flags
                flag_str = ""
                if flags & 0x01: flag_str += "F"  # FIN
                if flags & 0x02: flag_str += "S"  # SYN
                if flags & 0x04: flag_str += "R"  # RST
                if flags & 0x08: flag_str += "P"  # PSH
                if flags & 0x10: flag_str += "A"  # ACK
                if flags & 0x20: flag_str += "U"  # URG
                if flags & 0x40: flag_str += "E"  # ECE
                if flags & 0x80: flag_str += "C"  # CWR
                
                info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{flag_str}]"
                
                # Check for common services
                if dst_port == 80 or src_port == 80:
                    protocol = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
                elif dst_port == 22 or src_port == 22:
                    protocol = "SSH"
                elif dst_port == 21 or src_port == 21:
                    protocol = "FTP"
                elif dst_port == 25 or src_port == 25:
                    protocol = "SMTP"
                elif dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                else:
                    protocol = "TCP"
                
            elif packet.haslayer(scapy.UDP):
                base_protocol = "UDP"
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                
                info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                
                # Check for common services
                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
                    protocol = "DHCP"
                else:
                    protocol = "UDP"
                
            elif packet.haslayer(scapy.ICMP):
                protocol = "ICMP"
                icmp_type = packet[scapy.ICMP].type
                icmp_code = packet[scapy.ICMP].code
                
                # Determine ICMP message type
                if icmp_type == 0:
                    info = f"Echo Reply (type={icmp_type}, code={icmp_code})"
                elif icmp_type == 8:
                    info = f"Echo Request (type={icmp_type}, code={icmp_code})"
                else:
                    info = f"Type: {icmp_type}, Code: {icmp_code}"
            else:
                protocol = "IP"
                info = f"{src_ip} → {dst_ip}"
        elif packet.haslayer(scapy.ARP):
            protocol = "ARP"
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            
            # Determine ARP operation
            if packet[scapy.ARP].op == 1:
                info = f"Who has {dst_ip}? Tell {src_ip}"
            elif packet[scapy.ARP].op == 2:
                info = f"{src_ip} is at {packet[scapy.ARP].hwsrc}"
            else:
                info = f"ARP operation {packet[scapy.ARP].op}"
        elif packet.haslayer(scapy.Ether):
            protocol = "Ethernet"
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst
            info = f"{src_mac} → {dst_mac}"
        
        # Update protocol statistics
        if protocol not in traffic_status["traffic_data"]["protocols"]:
            traffic_status["traffic_data"]["protocols"][protocol] = {
                "bytes": 0,
                "packets": 0
            }
        
        traffic_status["traffic_data"]["protocols"][protocol]["bytes"] += length
        traffic_status["traffic_data"]["protocols"][protocol]["packets"] += 1
        
        # Update connection tracking
        if src_port and dst_port:
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            if conn_key not in traffic_status["traffic_data"]["connections"]:
                traffic_status["traffic_data"]["connections"][conn_key] = {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "bytes": 0,
                    "packets": 0
                }
            
            conn = traffic_status["traffic_data"]["connections"][conn_key]
            conn["bytes"] += length
            conn["packets"] += 1
            conn["last_seen"] = timestamp
        
        # Add to packet history (limit to max_packets)
        packet_info = {
            "id": traffic_status["packets_captured"],
            "timestamp": timestamp.strftime("%H:%M:%S.%f")[:-3],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": length,
            "info": info
        }
        
        traffic_status["traffic_data"]["packet_history"].append(packet_info)
        if len(traffic_status["traffic_data"]["packet_history"]) > traffic_status["max_packets"]:
            traffic_status["traffic_data"]["packet_history"].pop(0)
    
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def is_local_ip(ip):
    """Check if an IP address is local"""
    if not ip:
        return False
    
    # Check if it's a private IP address
    if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168."):
        return True
    
    # Check if it's localhost
    if ip == "127.0.0.1" or ip == "::1":
        return True
    
    return False

def monitor_traffic(interface=None, capture_filter="", max_packets=1000):
    """
    Monitor network traffic on the specified interface
    
    Args:
        interface: Network interface to monitor (None for default)
        capture_filter: BPF filter string to apply
        max_packets: Maximum number of packets to store in history
    
    Returns:
        dict: Status of the monitoring operation
    """
    global traffic_status, active_monitors, stop_capture
    
    if not SCAPY_AVAILABLE:
        return {
            "status": "error",
            "message": "Scapy is not available. Please install it with 'pip install scapy'"
        }
    
    # Stop any existing capture
    stop_capture.set()
    time.sleep(0.5)  # Give time for existing capture to stop
    stop_capture.clear()
    
    # Generate a unique ID for this monitoring session
    monitor_id = f"monitor_{int(time.time())}"
    
    # Reset traffic data
    reset_traffic_data()
    
    # Update status
    traffic_status["status"] = "starting"
    traffic_status["start_time"] = datetime.now().isoformat()
    traffic_status["monitoring_interface"] = interface
    traffic_status["capture_filter"] = capture_filter
    traffic_status["max_packets"] = max_packets
    
    # Start packet capture in a separate thread
    def capture_thread():
        try:
            traffic_status["status"] = "monitoring"
            logger.info(f"Starting traffic monitoring on interface {interface} with filter '{capture_filter}'")
            
            # Start packet capture
            scapy.sniff(
                iface=interface,
                filter=capture_filter if capture_filter else None,
                prn=packet_callback,
                store=False,
                stop_filter=lambda _: stop_capture.is_set()
            )
            
            # Update status when finished
            traffic_status["status"] = "idle"
            logger.info("Traffic monitoring stopped")
            
            # Remove from active monitors
            if monitor_id in active_monitors:
                del active_monitors[monitor_id]
                
        except Exception as e:
            traffic_status["status"] = "error"
            logger.error(f"Error monitoring traffic: {e}")
    
    # Start the thread
    thread = threading.Thread(target=capture_thread)
    thread.daemon = True
    thread.start()
    
    # Store the thread in active monitors
    active_monitors[monitor_id] = thread
    
    return {
        "status": "started",
        "monitor_id": monitor_id
    }

def stop_traffic_monitor():
    """Stop traffic monitoring"""
    global traffic_status, active_monitors, stop_capture
    
    if not SCAPY_AVAILABLE:
        return {
            "status": "error",
            "message": "Scapy is not available"
        }
    
    # Signal all captures to stop
    stop_capture.set()
    
    # Update status
    traffic_status["status"] = "stopping"
    logger.info("Stopping traffic monitoring")
    
    # Wait briefly for captures to stop
    time.sleep(0.5)
    
    # Clear active monitors
    active_monitors.clear()
    
    # Update status
    traffic_status["status"] = "idle"
    
    return {
        "status": "stopped"
    }

def get_network_usage():
    """Get current network usage statistics"""
    global traffic_status
    
    # Calculate rates
    now = datetime.now()
    start_time = datetime.fromisoformat(traffic_status["start_time"]) if traffic_status["start_time"] else now
    elapsed_seconds = max(1, (now - start_time).total_seconds())
    
    total_bytes = traffic_status["traffic_data"]["total_bytes"]
    incoming_bytes = traffic_status["traffic_data"]["incoming_bytes"]
    outgoing_bytes = traffic_status["traffic_data"]["outgoing_bytes"]
    
    # Calculate bytes per second
    bps = total_bytes / elapsed_seconds
    incoming_bps = incoming_bytes / elapsed_seconds
    outgoing_bps = outgoing_bytes / elapsed_seconds
    
    # Format as human-readable
    def format_bytes(bytes_value):
        if bytes_value < 1024:
            return f"{bytes_value:.2f} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.2f} KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.2f} MB"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"
    
    def format_bps(bps_value):
        if bps_value < 1024:
            return f"{bps_value:.2f} B/s"
        elif bps_value < 1024 * 1024:
            return f"{bps_value / 1024:.2f} KB/s"
        elif bps_value < 1024 * 1024 * 1024:
            return f"{bps_value / (1024 * 1024):.2f} MB/s"
        else:
            return f"{bps_value / (1024 * 1024 * 1024):.2f} GB/s"
    
    # Get top protocols
    protocols = traffic_status["traffic_data"]["protocols"]
    top_protocols = sorted(protocols.items(), key=lambda x: x[1]["bytes"], reverse=True)
    
    # Get top source IPs
    src_ips = traffic_status["traffic_data"]["src_ips"]
    top_sources = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Get top destination IPs
    dst_ips = traffic_status["traffic_data"]["dst_ips"]
    top_destinations = sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Get active connections
    connections = traffic_status["traffic_data"]["connections"]
    active_connections = []
    
    for conn_key, conn in connections.items():
        # Only include connections seen in the last 60 seconds
        if (now - conn["last_seen"]).total_seconds() < 60:
            active_connections.append({
                "src_ip": conn["src_ip"],
                "src_port": conn["src_port"],
                "dst_ip": conn["dst_ip"],
                "dst_port": conn["dst_port"],
                "protocol": conn["protocol"],
                "bytes": conn["bytes"],
                "bytes_formatted": format_bytes(conn["bytes"]),
                "packets": conn["packets"],
                "duration": (conn["last_seen"] - conn["first_seen"]).total_seconds()
            })
    
    # Sort connections by bytes
    active_connections.sort(key=lambda x: x["bytes"], reverse=True)
    
    return {
        "status": traffic_status["status"],
        "monitoring_interface": traffic_status["monitoring_interface"],
        "capture_filter": traffic_status["capture_filter"],
        "start_time": traffic_status["start_time"],
        "elapsed_time": elapsed_seconds,
        "packets_captured": traffic_status["packets_captured"],
        "total_bytes": total_bytes,
        "total_bytes_formatted": format_bytes(total_bytes),
        "incoming_bytes": incoming_bytes,
        "incoming_bytes_formatted": format_bytes(incoming_bytes),
        "outgoing_bytes": outgoing_bytes,
        "outgoing_bytes_formatted": format_bytes(outgoing_bytes),
        "bytes_per_second": bps,
        "bytes_per_second_formatted": format_bps(bps),
        "incoming_bytes_per_second": incoming_bps,
        "incoming_bytes_per_second_formatted": format_bps(incoming_bps),
        "outgoing_bytes_per_second": outgoing_bps,
        "outgoing_bytes_per_second_formatted": format_bps(outgoing_bps),
        "top_protocols": [
            {
                "protocol": protocol,
                "bytes": data["bytes"],
                "bytes_formatted": format_bytes(data["bytes"]),
                "packets": data["packets"],
                "percentage": (data["bytes"] / total_bytes * 100) if total_bytes > 0 else 0
            }
            for protocol, data in top_protocols
        ],
        "top_sources": [
            {
                "ip": ip,
                "bytes": bytes_value,
                "bytes_formatted": format_bytes(bytes_value),
                "percentage": (bytes_value / total_bytes * 100) if total_bytes > 0 else 0
            }
            for ip, bytes_value in top_sources
        ],
        "top_destinations": [
            {
                "ip": ip,
                "bytes": bytes_value,
                "bytes_formatted": format_bytes(bytes_value),
                "percentage": (bytes_value / total_bytes * 100) if total_bytes > 0 else 0
            }
            for ip, bytes_value in top_destinations
        ],
        "active_connections": active_connections,
        "recent_packets": traffic_status["traffic_data"]["packet_history"]
    }

def get_available_interfaces():
    """Get list of available network interfaces"""
    if not SCAPY_AVAILABLE:
        return []
    
    interfaces = []
    try:
        for iface in scapy.get_if_list():
            try:
                ip = scapy.get_if_addr(iface)
                interfaces.append({
                    "name": iface,
                    "ip": ip if ip and ip != "0.0.0.0" else "N/A"
                })
            except Exception as e:
                logger.debug(f"Error getting IP for interface {iface}: {e}")
                interfaces.append({
                    "name": iface,
                    "ip": "N/A"
                })
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
    
    return interfaces
