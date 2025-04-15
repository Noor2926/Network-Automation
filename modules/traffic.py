import time
import threading
import socket
import os
import json
from datetime import datetime
from collections import defaultdict

# Try to import optional dependencies
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Global variables for traffic monitoring
traffic_status = {
    "status": "idle",
    "start_time": None,
    "packets_captured": 0,
    "monitoring_interface": None,
    "traffic_data": {
        "total_bytes": 0,
        "incoming_bytes": 0,
        "outgoing_bytes": 0,
        "protocols": {},
        "top_talkers": {},
        "packet_history": []
    }
}

# Keep track of active monitoring threads
active_monitors = {}

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
        "top_talkers": {},
        "packet_history": []
    }

def packet_callback(packet):
    """Process captured packet and update traffic statistics"""
    global traffic_status
    
    if not SCAPY_AVAILABLE:
        return
    
    try:
        # Increment packet counter
        traffic_status["packets_captured"] += 1
        
        # Extract packet information
        timestamp = datetime.now().isoformat()
        src_ip = None
        dst_ip = None
        protocol = "Unknown"
        length = len(packet)
        
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
            
            # Update top talkers
            if src_ip not in traffic_status["traffic_data"]["top_talkers"]:
                traffic_status["traffic_data"]["top_talkers"][src_ip] = {
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "packets_sent": 0,
                    "packets_received": 0
                }
            
            if dst_ip not in traffic_status["traffic_data"]["top_talkers"]:
                traffic_status["traffic_data"]["top_talkers"][dst_ip] = {
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "packets_sent": 0,
                    "packets_received": 0
                }
            
            traffic_status["traffic_data"]["top_talkers"][src_ip]["bytes_sent"] += length
            traffic_status["traffic_data"]["top_talkers"][src_ip]["packets_sent"] += 1
            traffic_status["traffic_data"]["top_talkers"][dst_ip]["bytes_received"] += length
            traffic_status["traffic_data"]["top_talkers"][dst_ip]["packets_received"] += 1
            
            # Determine protocol
            if packet.haslayer(scapy.TCP):
                protocol = "TCP"
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                
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
            elif packet.haslayer(scapy.UDP):
                protocol = "UDP"
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                
                # Check for common services
                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
                    protocol = "DHCP"
            elif packet.haslayer(scapy.ICMP):
                protocol = "ICMP"
            
            # Update protocol statistics
            if protocol not in traffic_status["traffic_data"]["protocols"]:
                traffic_status["traffic_data"]["protocols"][protocol] = {
                    "bytes": 0,
                    "packets": 0
                }
            
            traffic_status["traffic_data"]["protocols"][protocol]["bytes"] += length
            traffic_status["traffic_data"]["protocols"][protocol]["packets"] += 1
        
        # Add to packet history (keep only the last 100 packets)
        packet_info = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": length
        }
        
        traffic_status["traffic_data"]["packet_history"].append(packet_info)
        if len(traffic_status["traffic_data"]["packet_history"]) > 100:
            traffic_status["traffic_data"]["packet_history"] = traffic_status["traffic_data"]["packet_history"][-100:]
    
    except Exception as e:
        print(f"Error processing packet: {e}")

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

def monitor_traffic(interface=None, duration=None):
    """
    Monitor network traffic on the specified interface
    
    Args:
        interface: Network interface to monitor (None for default)
        duration: Duration in seconds to monitor (None for indefinite)
    
    Returns:
        str: ID of the monitoring session
    """
    global traffic_status, active_monitors
    
    if not SCAPY_AVAILABLE:
        return {
            "status": "error",
            "message": "Scapy is not available. Please install it with 'pip install scapy'"
        }
    
    # Generate a unique ID for this monitoring session
    monitor_id = f"monitor_{int(time.time())}"
    
    # Reset traffic data
    reset_traffic_data()
    
    # Update status
    traffic_status["status"] = "starting"
    traffic_status["start_time"] = datetime.now().isoformat()
    traffic_status["monitoring_interface"] = interface
    
    # Start packet capture in a separate thread
    def capture_thread():
        try:
            traffic_status["status"] = "monitoring"
            
            # Start packet capture
            scapy.sniff(
                iface=interface,
                prn=packet_callback,
                store=False,
                timeout=duration
            )
            
            # Update status when finished
            traffic_status["status"] = "idle"
            
            # Remove from active monitors
            if monitor_id in active_monitors:
                del active_monitors[monitor_id]
                
        except Exception as e:
            traffic_status["status"] = "error"
            print(f"Error monitoring traffic: {e}")
    
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

def stop_traffic_monitor(monitor_id=None):
    """Stop traffic monitoring"""
    global traffic_status, active_monitors
    
    if not SCAPY_AVAILABLE:
        return {
            "status": "error",
            "message": "Scapy is not available"
        }
    
    # If no monitor ID is specified, stop all monitors
    if monitor_id is None:
        # There's no direct way to stop scapy.sniff(), but we can set the status
        traffic_status["status"] = "stopping"
        
        # Wait for threads to finish
        for thread_id, thread in list(active_monitors.items()):
            if thread.is_alive():
                # We can't forcibly stop the thread, but we can wait for it to finish
                # This is a limitation of scapy.sniff()
                pass
        
        # Clear active monitors
        active_monitors.clear()
        
        return {
            "status": "stopped"
        }
    
    # Stop specific monitor
    if monitor_id in active_monitors:
        # There's no direct way to stop scapy.sniff(), but we can set the status
        traffic_status["status"] = "stopping"
        
        # Wait for thread to finish
        thread = active_monitors[monitor_id]
        if thread.is_alive():
            # We can't forcibly stop the thread, but we can wait for it to finish
            # This is a limitation of scapy.sniff()
            pass
        
        # Remove from active monitors
        del active_monitors[monitor_id]
        
        return {
            "status": "stopped"
        }
    
    return {
        "status": "error",
        "message": f"Monitor {monitor_id} not found"
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
    top_protocols = sorted(protocols.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    
    # Get top talkers
    talkers = traffic_status["traffic_data"]["top_talkers"]
    top_talkers = sorted(talkers.items(), key=lambda x: x[1]["bytes_sent"] + x[1]["bytes_received"], reverse=True)[:5]
    
    return {
        "status": traffic_status["status"],
        "monitoring_interface": traffic_status["monitoring_interface"],
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
        "top_talkers": [
            {
                "ip": ip,
                "bytes_sent": data["bytes_sent"],
                "bytes_sent_formatted": format_bytes(data["bytes_sent"]),
                "bytes_received": data["bytes_received"],
                "bytes_received_formatted": format_bytes(data["bytes_received"]),
                "total_bytes": data["bytes_sent"] + data["bytes_received"],
                "total_bytes_formatted": format_bytes(data["bytes_sent"] + data["bytes_received"]),
                "packets_sent": data["packets_sent"],
                "packets_received": data["packets_received"]
            }
            for ip, data in top_talkers
        ]
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
                if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                    interfaces.append({
                        "name": iface,
                        "ip": ip
                    })
            except:
                pass
    except:
        pass
    
    return interfaces