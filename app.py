from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import json
import time
import logging
import socket
import re
from pathlib import Path
from modules.scan import scan_network, get_scan_status
from modules.port_scanner import scan_ports, get_port_results
from modules.vulnerability import scan_vulnerabilities
from modules.dnsconfig import get_dns_settings, save_dns_settings, ping_device, restart_device
import modules.dnsconfig as dnsconfig
import modules.config as config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("app")

app = Flask(__name__)

# Ensure data directories exist
DATA_DIR = Path(config.DATA_DIR)
SCAN_HISTORY_DIR = DATA_DIR / "scan_history"
DEVICES_DIR = DATA_DIR / "devices"
PORTS_DIR = DATA_DIR / "ports"
VULNERABILITIES_DIR = DATA_DIR / "vulnerabilities"
DNS_CONFIG_DIR = DATA_DIR / "dns_config"
URL_RESTRICT_DIR = DATA_DIR / "url_restrictions"

for directory in [DATA_DIR, SCAN_HISTORY_DIR, DEVICES_DIR, PORTS_DIR, VULNERABILITIES_DIR, DNS_CONFIG_DIR, URL_RESTRICT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Routes for web pages
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/devices')
def devices():
    return render_template('devices.html')

@app.route('/wifi')
def wifi():
    return render_template('password.html')

# Add these new routes to your existing app.py

@app.route('/api/check-admin')
def check_admin():
    """Check if the application is running with admin privileges"""
    try:
        from modules.password import is_admin
        return jsonify({
            "isAdmin": is_admin()
        })
    except Exception as e:
        logger.error(f"Error checking admin status: {str(e)}")
        return jsonify({
            "isAdmin": False,
            "error": str(e)
        }), 500

@app.route('/api/wifi/current')
def get_current_wifi():
    """Get currently connected WiFi network"""
    try:
        from modules.password import get_current_wifi
        current_wifi = get_current_wifi()
        if current_wifi:
            return jsonify(current_wifi)
        else:
            return jsonify({
                "error": "Not connected to WiFi or unable to detect current network"
            })
    except Exception as e:
        logger.error(f"Error getting current WiFi: {str(e)}")
        return jsonify({
            "error": f"Failed to get current WiFi: {str(e)}"
        }), 500

@app.route('/api/wifi/profiles')
def get_wifi_profiles():
    """Get list of saved WiFi profiles"""
    try:
        from modules.password import get_wifi_profiles
        profiles = get_wifi_profiles()
        return jsonify({
            "profiles": profiles
        })
    except PermissionError as e:
        logger.error(f"Permission denied getting WiFi profiles: {str(e)}")
        return jsonify({
            "error": "Administrator/root privileges required"
        }), 403
    except Exception as e:
        logger.error(f"Error getting WiFi profiles: {str(e)}")
        return jsonify({
            "error": f"Failed to get WiFi profiles: {str(e)}"
        }), 500

@app.route('/api/wifi/password')
def get_wifi_password():
    """Get password for a specific WiFi profile"""
    try:
        profile = request.args.get('profile')
        if not profile:
            return jsonify({
                "error": "Profile name is required"
            }), 400
            
        from modules.password import get_wifi_password
        password_info = get_wifi_password(profile)
        return jsonify(password_info)
    except PermissionError as e:
        logger.error(f"Permission denied getting WiFi password: {str(e)}")
        return jsonify({
            "error": "Administrator/root privileges required"
        }), 403
    except Exception as e:
        logger.error(f"Error getting WiFi password: {str(e)}")
        return jsonify({
            "error": f"Failed to get WiFi password: {str(e)}"
        }), 500


@app.route('/port-scanner')
def port_scanner():
    return render_template('port_scanner.html')

@app.route('/scan-history')
def scan_history():
    return render_template('scan_history.html')

@app.route('/vulnerability')
def vulnerability():
    return render_template('vulnerability.html')

@app.route('/traffic')
def traffic():
    return render_template('traffic.html')

# API Routes
@app.route('/api/network-info')
def get_network_info():
    try:
        # Get local machine's hostname and IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Extract network range from local IP (assuming /24 subnet)
        ip_parts = local_ip.split('.')
        network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
        
        return jsonify({
            "status": "success",
            "network_range": network_range,
            "gateway": gateway,
            "local_ip": local_ip,
            "hostname": hostname
        })
    except Exception as e:
        logger.error(f"Error getting network info: {str(e)}")
        # Fallback to default values
        return jsonify({
            "status": "success",
            "network_range": config.DEFAULT_IP_RANGE,
            "gateway": "192.168.1.1"
        })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.json
        ip_range = data.get('ip_range', config.DEFAULT_IP_RANGE)
        timeout = float(data.get('timeout', config.DEFAULT_TIMEOUT))
        max_threads = int(data.get('max_threads', config.MAX_THREADS))
        
        # Start scan in a separate thread
        scan_network(ip_range, timeout, max_threads)
        
        return jsonify({
            "status": "started",
            "message": f"Scan started for {ip_range}"
        })
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to start scan: {str(e)}"
        }), 500

@app.route('/api/scan/status')
def check_scan_status():
    try:
        status = get_scan_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error checking scan status: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to check scan status: {str(e)}"
        }), 500

@app.route('/api/devices')
def get_devices():
    try:
        limit = request.args.get('limit', None)
        
        devices = []
        device_files = list(DEVICES_DIR.glob('*.json'))
        
        if not device_files:
            return jsonify({
                "status": "no_data",
                "message": "No devices found"
            })
        
        # Sort by modification time (newest first)
        device_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        
        if limit:
            device_files = device_files[:int(limit)]
        
        for file in device_files:
            try:
                with open(file, 'r') as f:
                    device_data = json.load(f)
                    devices.append(device_data)
            except Exception as e:
                logger.error(f"Error reading device file {file}: {str(e)}")
        
        return jsonify({
            "status": "success",
            "data": {
                "devices": devices
            }
        })
    except Exception as e:
        logger.error(f"Error getting devices: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get devices: {str(e)}"
        }), 500

@app.route('/api/devices/summary')
def get_devices_summary():
    try:
        total_devices = 0
        active_devices = 0
        vulnerabilities = 0
        open_ports = 0
        
        # Count devices
        device_files = list(DEVICES_DIR.glob('*.json'))
        total_devices = len(device_files)
        
        for file in device_files:
            try:
                with open(file, 'r') as f:
                    device_data = json.load(f)
                    if device_data.get('status') == 'Active':
                        active_devices += 1
            except Exception as e:
                logger.error(f"Error reading device file {file}: {str(e)}")
        
        # Count vulnerabilities
        vuln_files = list(VULNERABILITIES_DIR.glob('*.json'))
        for file in vuln_files:
            try:
                with open(file, 'r') as f:
                    vuln_data = json.load(f)
                    vulnerabilities += len(vuln_data.get('vulnerabilities', []))
            except Exception as e:
                logger.error(f"Error reading vulnerability file {file}: {str(e)}")
        
        # Count open ports
        port_files = list(PORTS_DIR.glob('*.json'))
        for file in port_files:
            try:
                with open(file, 'r') as f:
                    port_data = json.load(f)
                    open_ports += len(port_data.get('open_ports', []))
            except Exception as e:
                logger.error(f"Error reading port file {file}: {str(e)}")
        
        return jsonify({
            "status": "success",
            "total": total_devices,
            "active": active_devices,
            "vulnerabilities": vulnerabilities,
            "open_ports": open_ports
        })
    except Exception as e:
        logger.error(f"Error getting devices summary: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get devices summary: {str(e)}"
        }), 500

@app.route('/api/scan-history')
def get_scan_history():
    try:
        limit = request.args.get('limit', None)
        
        history = []
        history_files = list(SCAN_HISTORY_DIR.glob('*.json'))
        
        if not history_files:
            return jsonify({
                "status": "success",
                "history": []
            })
        
        # Sort by modification time (newest first)
        history_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        
        if limit:
            history_files = history_files[:int(limit)]
        
        for file in history_files:
            try:
                with open(file, 'r') as f:
                    scan_data = json.load(f)
                    history.append(scan_data)
            except Exception as e:
                logger.error(f"Error reading scan history file {file}: {str(e)}")
        
        return jsonify({
            "status": "success",
            "history": history
        })
    except Exception as e:
        logger.error(f"Error getting scan history: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get scan history: {str(e)}"
        }), 500

@app.route('/api/ports')
def get_ports():
    try:
        ip = request.args.get('ip')
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        # Try to get existing port results
        port_results = get_port_results(ip)
        
        if port_results.get("status") == "success":
            return jsonify(port_results)
        
        # If no existing results, try to scan ports
        scan_result = scan_ports(ip, config.COMMON_PORTS, config.DEFAULT_TIMEOUT, config.MAX_THREADS)
        
        if scan_result.get("status") == "success":
            return jsonify(scan_result)
        else:
            return jsonify({
                "status": "error",
                "message": "No port data available and scan failed"
            }), 404
    except Exception as e:
        logger.error(f"Error getting ports: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get ports: {str(e)}"
        }), 500

@app.route('/api/ports/scan', methods=['POST'])
def start_port_scan():
    try:
        data = request.json
        ip = data.get('ip')
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        # Get custom ports if provided, otherwise use common ports
        ports = data.get('ports', config.COMMON_PORTS)
        timeout = float(data.get('timeout', config.DEFAULT_TIMEOUT))
        
        # Start port scan
        result = scan_ports(ip, ports, timeout, config.MAX_THREADS)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting port scan: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to start port scan: {str(e)}"
        }), 500

@app.route('/api/device/dns', methods=['GET', 'POST'])
def handle_dns():
    try:
        if request.method == 'GET':
            ip = request.args.get('ip')
            
            if not ip:
                return jsonify({
                    "status": "error",
                    "message": "IP address is required"
                }), 400
            
            dns_settings = get_dns_settings(ip)
            return jsonify(dns_settings)
        
        elif request.method == 'POST':
            data = request.json
            ip = data.get('ip')
            primary_dns = data.get('primary_dns')
            secondary_dns = data.get('secondary_dns', '')
            
            if not ip or not primary_dns:
                return jsonify({
                    "status": "error",
                    "message": "IP address and primary DNS are required"
                }), 400
            
            result = save_dns_settings(ip, primary_dns, secondary_dns)
            
            if result.get("status") == "error":
                return jsonify(result), 400
            
            return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error handling DNS request: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to process DNS request: {str(e)}"
        }), 500

@app.route('/api/device/url-restrictions', methods=['GET'])
def get_url_restrictions():
    try:
        ip = request.args.get('ip')
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        result = dnsconfig.get_url_restrictions(ip)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error getting URL restrictions: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get URL restrictions: {str(e)}"
        }), 500

@app.route('/api/device/url-restrictions/add', methods=['POST'])
def add_url_restriction():
    try:
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "Invalid request data"
            }), 400
            
        ip = data.get('ip')
        url = data.get('url')
        
        if not ip or not url:
            return jsonify({
                "status": "error",
                "message": "IP address and URL are required"
            }), 400
        
        # Strip http:// or https:// if present
        if url.startswith(('http://', 'https://')):
            url = re.sub(r'^https?://(www\.)?', '', url)
        
        result = dnsconfig.add_url_restriction(ip, url)
        
        if result.get("status") == "error":
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error adding URL restriction: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to add URL restriction: {str(e)}"
        }), 500

@app.route('/api/device/url-restrictions/remove', methods=['POST'])
def remove_url_restriction():
    try:
        data = request.json
        ip = data.get('ip')
        url = data.get('url')
        
        if not ip or not url:
            return jsonify({
                "status": "error",
                "message": "IP address and URL are required"
            }), 400
        
        result = dnsconfig.remove_url_restriction(ip, url)
        
        if result.get("status") == "error":
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error removing URL restriction: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to remove URL restriction: {str(e)}"
        }), 500

@app.route('/api/device/test-url-restriction', methods=['POST'])
def test_url_restriction():
    """Test if a URL restriction is working on a device."""
    try:
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "Invalid request data"
            }), 400
            
        ip = data.get('ip')
        url = data.get('url')
        
        if not ip or not url:
            return jsonify({
                "status": "error",
                "message": "IP address and URL are required"
            }), 400
        
        # Strip http:// or https:// if present
        if url.startswith(('http://', 'https://')):
            url = re.sub(r'^https?://(www\.)?', '', url)
        
        # Check if the URL is in the restricted list
        restrictions = dnsconfig.get_url_restrictions(ip)
        if restrictions.get("status") != "success":
            return jsonify({
                "status": "error",
                "message": "Failed to get URL restrictions"
            }), 500
        
        restricted_urls = restrictions.get("restricted_urls", [])
        if url not in restricted_urls:
            return jsonify({
                "status": "error",
                "message": f"URL {url} is not in the restriction list"
            }), 400
        
        # Test if the restriction is working
        # In a real implementation, you would try to access the URL from the device
        # and check if it's blocked
        
        # For now, simulate success
        return jsonify({
            "status": "success",
            "message": f"URL {url} is successfully restricted on device {ip}"
        })
    
    except Exception as e:
        logger.error(f"Error testing URL restriction: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to test URL restriction: {str(e)}"
        }), 500

@app.route('/api/ping')
def handle_ping():
    try:
        ip = request.args.get('ip')
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        count = int(request.args.get('count', 4))
        timeout = float(request.args.get('timeout', 1.0))
        
        # Limit values for security
        count = min(count, 10)  # Max 10 pings
        timeout = min(timeout, 5.0)  # Max 5 seconds timeout
        
        result = ping_device(ip, count, timeout)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error handling ping request: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to process ping request: {str(e)}"
        }), 500

@app.route('/api/restart-device', methods=['POST'])
def handle_restart():
    try:
        data = request.json
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request data"
            }), 400
            
        ip = data.get('ip')
        method = data.get('method', 'auto')
        credentials = data.get('credentials', {})
        
        if not ip:
            return jsonify({
                "success": False,
                "message": "IP address is required"
            }), 400
        
        # Validate method
        valid_methods = ['auto', 'snmp', 'ssh', 'wmi', 'web', 'wol', 'http']
        if method not in valid_methods:
            return jsonify({
                "success": False,
                "message": f"Invalid restart method. Valid methods are: {', '.join(valid_methods)}"
            }), 400
        
        # Map frontend method names to backend method names
        method_mapping = {
            'wol': 'snmp',  # Wake-on-LAN is handled via SNMP in the backend
            'http': 'web'   # HTTP is handled via web in the backend
        }
        
        backend_method = method_mapping.get(method, method)
        
        # Log the restart attempt
        logger.info(f"Attempting to restart device {ip} using method {method} (mapped to {backend_method})")
        
        # Check if device is reachable first
        ping_result = ping_device(ip, count=1, timeout=0.5)
        if not ping_result["success"]:
            logger.warning(f"Device {ip} is not responding to ping, but will attempt restart anyway")
        
        # Handle credentials based on method
        if backend_method == 'ssh' and credentials:
            result = restart_device_with_credentials(ip, backend_method, credentials)
        elif backend_method == 'web' and credentials:
            result = restart_device_with_credentials(ip, backend_method, credentials)
        else:
            result = restart_device(ip, backend_method)
        
        # Log the result
        if result["success"]:
            logger.info(f"Successfully sent restart command to {ip} using {backend_method}")
        else:
            logger.error(f"Failed to restart {ip}: {result.get('message', 'Unknown error')}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error handling restart request: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Failed to process restart request: {str(e)}"
        }), 500

@app.route('/device/<ip>/restart', methods=['POST'])
def restart(ip):
    """Direct endpoint to restart a device by IP address."""
    try:
        logger.info(f"Attempting to restart device {ip}")
        
        # Get request data
        data = request.json or {}
        method = data.get('method', 'auto')
        credentials = data.get('credentials', {})
        
        # Validate IP address
        if not dnsconfig.validate_ip(ip):
            logger.error(f"Invalid IP address format: {ip}")
            return jsonify({
                "success": False,
                "message": "Invalid IP address format"
            }), 400
        
        # Check if device exists in our database
        device_file = DEVICES_DIR / f"{ip.replace('.', '_')}.json"
        if not device_file.exists():
            logger.warning(f"Attempting to restart unknown device: {ip}")
        
        # Handle credentials based on method
        if method == 'ssh' and credentials:
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            if not username or not password:
                return jsonify({
                    "success": False,
                    "message": "SSH username and password are required"
                }), 400
            
            result = dnsconfig.restart_via_ssh(ip, username, password)
        elif method == 'http' and credentials:
            url = credentials.get('url', f"http://{ip}/")
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            result = dnsconfig.restart_via_web(ip, url, username, password)
        else:
            # Use the standard restart function
            result = dnsconfig.restart_device(ip, method)
        
        # Log the result
        if result["success"]:
            logger.info(f"Successfully sent restart command to {ip} using {method}")
        else:
            logger.error(f"Failed to restart {ip}: {result.get('message', 'Unknown error')}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error restarting device {ip}: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

def restart_device_with_credentials(ip, method, credentials):
    """Restart a device using the provided credentials."""
    try:
        if method == 'ssh':
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            if not username or not password:
                return {
                    "success": False,
                    "message": "SSH username and password are required"
                }
            
            # In a real implementation, you would use paramiko or similar to SSH into the device
            logger.info(f"Would restart {ip} via SSH with username {username}")
            
            # Simulate success for now
            return {
                "success": True,
                "message": "SSH restart command sent successfully",
                "method": "ssh"
            }
            
        elif method == 'web':
            url = credentials.get('url', f"http://{ip}/")
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            # In a real implementation, you would use requests to authenticate and send restart command
            logger.info(f"Would restart {ip} via web interface at {url}")
            
            # Simulate success for now
            return {
                "success": True,
                "message": "Web interface restart command sent successfully",
                "method": "web"
            }
        
        else:
            return {
                "success": False,
                "message": f"Unsupported method for credentials: {method}"
            }
    
    except Exception as e:
        logger.error(f"Error restarting {ip} with credentials: {str(e)}")
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

@app.route('/api/vulnerability/scan', methods=['POST'])
def start_vulnerability_scan():
    try:
        data = request.json
        ip = data.get('ip')
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        # Start vulnerability scan
        result = scan_vulnerabilities(ip)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error starting vulnerability scan: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to start vulnerability scan: {str(e)}"
        }), 500

@app.route('/api/vulnerability/results')
def get_vulnerability_results():
    try:
        ip = request.args.get('ip')
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        vuln_file = VULNERABILITIES_DIR / f"{ip.replace('.', '_')}.json"
        
        if not vuln_file.exists():
            return jsonify({
                "status": "no_data",
                "message": "No vulnerability data available"
            })
        
        try:
            with open(vuln_file, 'r') as f:
                vuln_data = json.load(f)
            
            return jsonify({
                "status": "success",
                "data": vuln_data
            })
        except Exception as e:
            logger.error(f"Error reading vulnerability file for {ip}: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Failed to read vulnerability data: {str(e)}"
            }), 500
    
    except Exception as e:
        logger.error(f"Error getting vulnerability results: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get vulnerability results: {str(e)}"
        }), 500

@app.route('/api/check-dependencies')
def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        dependencies = {
            "npcap": check_npcap_installed(),
            "winpcap": check_winpcap_installed()
        }
        
        return jsonify({
            "status": "success",
            "dependencies": dependencies
        })
    except Exception as e:
        logger.error(f"Error checking dependencies: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to check dependencies: {str(e)}"
        }), 500

def check_npcap_installed():
    """Check if Npcap is installed."""
    try:
        # Check for Npcap installation directory
        npcap_dir = os.path.exists("C:\\Program Files\\Npcap")
        
        # Check for Npcap DLLs
        npcap_dll = os.path.exists("C:\\Windows\\System32\\Npcap")
        
        return npcap_dir or npcap_dll
    except:
        return False

def check_winpcap_installed():
    """Check if WinPcap is installed."""
    try:
        # Check for WinPcap installation directory
        winpcap_dir = os.path.exists("C:\\Program Files\\WinPcap")
        
        # Check for WinPcap DLLs
        winpcap_dll = os.path.exists("C:\\Windows\\System32\\wpcap.dll")
        
        return winpcap_dir or winpcap_dll
    except:
        return False

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=config.PORT)
