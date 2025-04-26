import scapy.all as scapy
import psutil
from colored import fg, attr
import time
import threading
import logging
from datetime import datetime
from collections import defaultdict
import socket
import requests
import netifaces
import json

# Configure logging
logging.basicConfig(
    filename="network_threats.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Dynamic tracking for suspicious entities and alerts
suspicious_ips = set()
suspicious_macs = set()
ip_packet_counts = defaultdict(int)
ip_port_activity = defaultdict(set)
alert_timestamps = {}  # Track last alert time for rate-limiting
ALERT_COOLDOWN = 60  # Seconds before re-alerting for same threat

# Monitoring state
is_monitoring = False
monitor_thread = None
stop_event = threading.Event()

# Function to get available network interfaces
def get_network_interfaces():
    try:
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())
    except Exception as e:
        logging.error(f"Error retrieving network interfaces: {e}")
        return []

# Function to get local IP and MAC
def get_local_ip_and_mac(interface=None):
    try:
        interfaces = psutil.net_if_addrs()
        
        # If no interface specified, try to find a suitable one
        if not interface:
            for iface in interfaces:
                if iface.lower() in ["wi-fi", "ethernet", "eth0", "wlan0"]:
                    interface = iface
                    break
            if not interface and interfaces:
                interface = list(interfaces.keys())[0]
        
        if interface not in interfaces:
            logging.error(f"Interface {interface} not found. Available: {list(interfaces.keys())}")
            return None, None
            
        ip, mac = None, None
        for addr in interfaces[interface]:
            if addr.family == socket.AF_INET:  # IPv4
                ip = addr.address
            if addr.family == psutil.AF_LINK:  # MAC
                mac = addr.address
        if not ip or not mac:
            logging.error(f"No IPv4 or MAC address found for interface {interface}")
            return None, None
        return ip, mac
    except Exception as e:
        logging.error(f"Error retrieving local IP/MAC: {e}")
        return None, None

# Function to get MAC vendor (basic lookup via API)
def get_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except:
        return "Unknown"

# Function to detect threats (display only, no mitigation)
def detect_threats(pkt, local_ip, local_mac, gateway_ip, interface):
    timestamp = time.time()
    formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # ARP Spoofing Detection
    if pkt.haslayer(scapy.ARP):
        if pkt[scapy.ARP].op == 2:  # ARP reply
            if pkt[scapy.ARP].psrc == gateway_ip and pkt[scapy.ARP].hwsrc != local_mac:
                threat_key = f"ARP:{pkt[scapy.ARP].hwsrc}:{pkt[scapy.ARP].psrc}"
                if threat_key not in alert_timestamps or time.time() - alert_timestamps[threat_key] > ALERT_COOLDOWN:
                    vendor = get_mac_vendor(pkt[scapy.ARP].hwsrc)
                    msg = f"[{formatted_time}] ARP Spoofing Detected: {pkt[scapy.ARP].hwsrc} ({vendor}) claims {pkt[scapy.ARP].psrc}"
                    print(f"{fg('red')}{msg}{attr('reset')}")
                    logging.warning(msg)
                    alert_timestamps[threat_key] = timestamp
                    suspicious_macs.add(pkt[scapy.ARP].hwsrc)
                    suspicious_ips.add(pkt[scapy.ARP].psrc)

    # IP-based threat detection
    if pkt.haslayer(scapy.IP):
        ip_src = pkt[scapy.IP].src
        ip_dst = pkt[scapy.IP].dst
        packet_len = len(pkt)
        ip_packet_counts[ip_src] += 1

        # Detect large packets
        if packet_len > 1500:
            threat_key = f"LargePacket:{ip_src}"
            if threat_key not in alert_timestamps or time.time() - alert_timestamps[threat_key] > ALERT_COOLDOWN:
                msg = f"[{formatted_time}] Large Packet: {ip_src} → {ip_dst} with size {packet_len} bytes"
                print(f"{fg('yellow')}{msg}{attr('reset')}")
                logging.info(msg)
                alert_timestamps[threat_key] = timestamp
                suspicious_ips.add(ip_src)

        # Detect flood
        if ip_packet_counts[ip_src] > 100:
            threat_key = f"Flood:{ip_src}"
            if threat_key not in alert_timestamps or time.time() - alert_timestamps[threat_key] > ALERT_COOLDOWN:
                msg = f"[{formatted_time}] Potential Flood Detected from {ip_src} ({ip_packet_counts[ip_src]} packets)"
                print(f"{fg('red')}{msg}{attr('reset')}")
                logging.warning(msg)
                alert_timestamps[threat_key] = timestamp
                suspicious_ips.add(ip_src)

        # Port scanning detection
        if pkt.haslayer(scapy.TCP) or pkt.haslayer(scapy.UDP):
            port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else pkt[scapy.UDP].dport
            ip_port_activity[ip_src].add(port)
            if len(ip_port_activity[ip_src]) > 10:
                threat_key = f"PortScan:{ip_src}"
                if threat_key not in alert_timestamps or time.time() - alert_timestamps[threat_key] > ALERT_COOLDOWN:
                    msg = f"[{formatted_time}] Port Scanning Detected from {ip_src} (Ports: {len(ip_port_activity[ip_src])})"
                    print(f"{fg('red')}{msg}{attr('reset')}")
                    logging.warning(msg)
                    alert_timestamps[threat_key] = timestamp
                    suspicious_ips.add(ip_src)

        # SYN Flood Detection
        if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags & 0x02:
            threat_key = f"SYNFlood:{ip_src}:{ip_dst}"
            if threat_key not in alert_timestamps or time.time() - alert_timestamps[threat_key] > ALERT_COOLDOWN:
                msg = f"[{formatted_time}] Potential SYN Flood from {ip_src} to {ip_dst}:{pkt[scapy.TCP].dport}"
                print(f"{fg('yellow')}{msg}{attr('reset')}")
                logging.info(msg)
                alert_timestamps[threat_key] = timestamp
                suspicious_ips.add(ip_src)

    # DNS Spoofing Detection
    if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 1:
        try:
            dns_resp = pkt[scapy.DNS].an
            if dns_resp and dns_resp.type == 1:
                threat_key = f"DNS:{ip_src}"
                if threat_key not in alert_timestamps or time.time() - alert_timestamps[threat_key] > ALERT_COOLDOWN:
                    msg = f"[{formatted_time}] Suspicious DNS Response from {ip_src}: {dns_resp.rrname} → {dns_resp.rdata}"
                    print(f"{fg('yellow')}{msg}{attr('reset')}")
                    logging.info(msg)
                    alert_timestamps[threat_key] = timestamp
                    suspicious_ips.add(ip_src)
        except:
            pass

# Function to monitor network traffic
def monitor_network(interface=None):
    global is_monitoring
    
    # Find a suitable interface if none provided
    interfaces = get_network_interfaces()
    if not interface:
        for iface in interfaces:
            if iface.lower() in ["wi-fi", "ethernet", "eth0", "wlan0"]:
                interface = iface
                break
        if not interface and interfaces:
            interface = interfaces[0]
    
    local_ip, local_mac = get_local_ip_and_mac(interface)
    if not local_ip or not local_mac:
        logging.error(f"Failed to get local IP/MAC for interface {interface}")
        is_monitoring = False
        return

    # Get gateway IP
    gateway_ip = None
    try:
        gateways = netifaces.gateways()
        gateway_ip = gateways['default'][netifaces.AF_INET][0]
    except:
        logging.error("Failed to get gateway IP")
    
    logging.info(f"Starting monitoring on {interface} (IP: {local_ip}, MAC: {local_mac}, Gateway: {gateway_ip})")
    
    try:
        # Use scapy's sniff function with a stop filter that checks our stop_event
        scapy.sniff(
            prn=lambda pkt: detect_threats(pkt, local_ip, local_mac, gateway_ip, interface),
            store=0,
            iface=interface,
            stop_filter=lambda x: stop_event.is_set()
        )
    except Exception as e:
        logging.error(f"Error during network monitoring: {e}")
    finally:
        is_monitoring = False
        logging.info("Network monitoring stopped")

# Start monitoring
def start_monitoring(interface=None):
    global is_monitoring, monitor_thread, stop_event
    
    if is_monitoring:
        return {"status": "error", "message": "Monitoring is already active"}
    
    # Reset the stop event
    stop_event.clear()
    
    # Start monitoring in a separate thread
    is_monitoring = True
    monitor_thread = threading.Thread(target=monitor_network, args=(interface,))
    monitor_thread.daemon = True
    monitor_thread.start()
    
    return {"status": "success", "message": "Network threat monitoring started"}

# Stop monitoring
def stop_monitoring():
    global is_monitoring, stop_event
    
    if not is_monitoring:
        return {"status": "error", "message": "Monitoring is not active"}
    
    # Signal the monitoring thread to stop
    stop_event.set()
    
    # Wait for the thread to finish (with timeout)
    if monitor_thread and monitor_thread.is_alive():
        monitor_thread.join(timeout=5)
    
    is_monitoring = False
    return {"status": "success", "message": "Network threat monitoring stopped"}

# Get formatted suspicious IPs for the API
def get_formatted_suspicious_ips():
    formatted_ips = []
    for ip in suspicious_ips:
        formatted_ips.append({
            "ip": ip,
            "hostname": "",  # Would resolve hostname in a full implementation
            "first_seen": time.time() - 3600  # Mock time for demonstration
        })
    return formatted_ips

# Get formatted suspicious MACs for the API
def get_formatted_suspicious_macs():
    formatted_macs = []
    for mac in suspicious_macs:
        formatted_macs.append({
            "mac": mac,
            "vendor": get_mac_vendor(mac),
            "first_seen": time.time() - 3600  # Mock time for demonstration
        })
    return formatted_macs

# Get formatted alerts for the API
def get_formatted_alerts():
    recent_alerts = []
    for key, timestamp in alert_timestamps.items():
        alert_type, details = key.split(':', 1)
        
        severity = "medium"
        if alert_type in ["ARP", "Flood", "PortScan"]:
            severity = "high"
        elif alert_type in ["SYNFlood", "DNS"]:
            severity = "medium"
        else:
            severity = "low"
        
        source = ""
        destination = ""
        if ":" in details:
            parts = details.split(":")
            source = parts[0]
            if len(parts) > 1:
                destination = parts[1]
        else:
            source = details
        
        message = f"{alert_type} threat detected from {source}"
        if destination:
            message += f" to {destination}"
        
        recent_alerts.append({
            "type": alert_type,
            "severity": severity,
            "source": source,
            "destination": destination,
            "message": message,
            "timestamp": timestamp
        })
    
    # Sort by timestamp (newest first)
    recent_alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    return recent_alerts

# For testing purposes - simulate some threats
def simulate_threats():
    global alert_timestamps
    
    # Add some sample data if there's nothing yet
    if not suspicious_ips and not alert_timestamps:
        suspicious_ips.add("192.168.1.100")
        suspicious_ips.add("192.168.1.105")
        suspicious_macs.add("00:1A:2B:3C:4D:5E")
        
        # Add some sample alerts
        current_time = time.time()
        alert_timestamps["ARP:00:1A:2B:3C:4D:5E:192.168.1.1"] = current_time - 120
        alert_timestamps["PortScan:192.168.1.100"] = current_time - 300
        alert_timestamps["SYNFlood:192.168.1.105:192.168.1.1"] = current_time - 180
        alert_timestamps["DNS:192.168.1.100"] = current_time - 240
        
        # Add some packet counts
        ip_packet_counts["192.168.1.100"] = 150
        ip_packet_counts["192.168.1.105"] = 75
        ip_packet_counts["192.168.1.1"] = 200
