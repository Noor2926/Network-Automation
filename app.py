
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
import os
import json
import time
import logging
import socket
import re
import subprocess
import platform
import yaml
from pathlib import Path
from modules.scan import scan_network, get_scan_status, get_all_devices
from modules.ping import ping_host, get_active_hosts
from modules.port_scanner import scan_ports, get_scan_status as get_port_scan_status
from modules.port_scanner import get_port_results, cancel_scan, test_connection, auto_detect_ports
from modules.email import send_email, send_sms
import modules.config as config
import modules.wifi_password as wifi_password
import modules.monitor as monitor
import modules.threats as threats
import netifaces

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("app")

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a secure random key in production

# Ensure data directories exist
DATA_DIR = Path("data")
SCAN_HISTORY_DIR = DATA_DIR / "scan_history"
DEVICES_DIR = DATA_DIR / "devices"
PORTS_DIR = DATA_DIR / "ports"
VULNERABILITIES_DIR = DATA_DIR / "vulnerabilities"

for directory in [DATA_DIR, SCAN_HISTORY_DIR, DEVICES_DIR, PORTS_DIR, VULNERABILITIES_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# PIN for authentication
VALID_PIN = "767676"

# Phone number for SMS alerts (replace with your number)
SMS_ALERT_PHONE = "9824762926"  # Placeholder; update with actual number

# Middleware to protect routes
@app.before_request
def require_pin():
    # Skip PIN check for static files, API routes, and PIN verification
    if request.path.startswith(('/static', '/api/verify-pin', '/pin', '/favicon.ico')):
        return
    # Check if user has verified PIN in session
    if not session.get('pin_verified'):
        return redirect(url_for('pin'))

@app.route('/pin')
def pin():
    """Render the PIN input page."""
    return render_template('pin.html')

@app.route('/api/verify-pin', methods=['POST'])
def verify_pin():
    """Verify the 6-digit PIN and send SMS alert on success."""
    try:
        data = request.json
        pin = data.get('pin')
        if not pin or not isinstance(pin, str) or not pin.isdigit() or len(pin) != 6:
            return jsonify({
                "status": "error",
                "message": "Invalid PIN. Please enter a 6-digit number."
            }), 400
        
        if pin == VALID_PIN:
            session['pin_verified'] = True
            client_ip = request.remote_addr
            sms_message = f"Success {client_ip} logged In."
            sms_result = send_sms(SMS_ALERT_PHONE, sms_message)
            if sms_result["status"] == "error":
                logger.warning(f"SMS alert failed: {sms_result['message']}")
            else:
                logger.info(f"SMS alert sent to {SMS_ALERT_PHONE} for IP {client_ip}")
            return jsonify({
                "status": "success",
                "message": "PIN verified successfully."
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Incorrect PIN. Please try again."
            }), 401
    except Exception as e:
        logger.error(f"Error verifying PIN: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to verify PIN: {str(e)}"
        }), 500

def get_wifi_ipv4():
    """Detect the IPv4 address and network range of the Wi-Fi adapter."""
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if "wi-fi" in iface.lower() or "wlan" in iface.lower():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if ip != "127.0.0.1":
                            # Assume /24 subnet (255.255.255.0) for simplicity
                            ip_parts = ip.split('.')
                            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                            logger.info(f"Detected Wi-Fi IPv4: {ip}, Network Range: {network_range}")
                            return {"ip": ip, "network_range": network_range}
        logger.warning("No Wi-Fi adapter with IPv4 address found")
        return {"ip": None, "network_range": "192.168.1.0/24"}
    except Exception as e:
        logger.error(f"Error detecting Wi-Fi IPv4: {str(e)}")
        return {"ip": None, "network_range": "192.168.1.0/24"}

@app.route('/api/network-info')
def get_network_info():
    """Return network information including Wi-Fi adapter's IP and network range."""
    try:
        wifi_info = get_wifi_ipv4()
        hostname = socket.gethostname()
        local_ip = wifi_info["ip"] or socket.gethostbyname(hostname)
        network_range = wifi_info["network_range"]
        
        return jsonify({
            "status": "success",
            "network_range": network_range,
            "gateway": network_range.split('/')[0].rsplit('.', 1)[0] + '.1',
            "local_ip": local_ip,
            "hostname": hostname
        })
    except Exception as e:
        logger.error(f"Error getting network info: {str(e)}")
        return jsonify({
            "status": "success",
            "network_range": "192.168.1.0/24",
            "gateway": "192.168.1.1",
            "local_ip": "unknown",
            "hostname": "unknown"
        })

@app.route('/configure')
def configure_network():
    """Render the network configuration page with auto-detected Wi-Fi IP."""
    wifi_info = get_wifi_ipv4()
    return render_template('configure_network.html', wifi_ip=wifi_info["ip"])

@app.route('/api/configure', methods=['POST'])
def configure_device():
    """Run Ansible playbook to configure network device."""
    try:
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body is required"
            }), 400

        ip = data.get('ip')
        hostname = data.get('hostname', 'router1')
        interface_name = data.get('interface_name', '1/1/1')
        interface_description = data.get('interface_description', 'Ansible Configured')
        interface_ip = data.get('interface_ip', '192.168.1.1')
        interface_mask = data.get('interface_mask', '255.255.255.255')
        ntp_server = data.get('ntp_server', 'pool.ntp.org')
        use_dhcp = data.get('use_dhcp', False)

        if not ip:
            return jsonify({
                "status": "error",
                "message": "Device IP address is required"
            }), 400

        # Validate device reachability
        try:
            socket.create_connection((ip, 830), timeout=5)
            logger.info(f"Device {ip} reachable on NETCONF port")
        except socket.error as e:
            logger.error(f"Device {ip} not reachable on NETCONF port: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Device {ip} is not reachable on NETCONF port: {str(e)}"
            }), 503

        # Create temporary inventory file
        inventory = {
            "all": {
                "hosts": {
                    ip: {
                        "ansible_user": "admin",
                        "ansible_password": "password",
                        "ansible_connection": "ansible.netcommon.netconf",
                        "ansible_network_os": "nokia.sros.sros"
                    }
                }
            }
        }
        inventory_path = Path("inventory.yml")
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory, f)

        # Update playbook with provided variables
        playbook_path = Path("configure_network.yml")
        if not playbook_path.exists():
            return jsonify({
                "status": "error",
                "message": "Playbook not found"
            }), 500

        # Prepare Ansible command
        cmd = [
            "ansible-playbook",
            "-i", str(inventory_path),
            str(playbook_path),
            "-e", f"device_hostname={hostname}",
            "-e", f"interface_name={interface_name}",
            "-e", f"interface_description={interface_description}",
            "-e", f"interface_ip={interface_ip}",
            "-e", f"interface_mask={interface_mask}",
            "-e", f"ntp_server={ntp_server}",
            "-e", f"use_dhcp={str(use_dhcp).lower()}"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Ansible playbook executed successfully for {ip}")
            return jsonify({
                "status": "success",
                "message": f"Configuration applied to {ip}",
                "output": result.stdout
            })
        except subprocess.CalledProcessError as e:
            logger.error(f"Ansible playbook failed: {e.stderr}")
            return jsonify({
                "status": "error",
                "message": f"Failed to apply configuration: {e.stderr}",
                "output": e.stdout
            }), 500
        finally:
            if inventory_path.exists():
                inventory_path.unlink()

    except Exception as e:
        logger.error(f"Error configuring device: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to configure device: {str(e)}"
        }), 500

# Existing routes (unchanged, included for reference)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/devices')
def devices():
    return render_template('devices.html')

@app.route('/port-scanner')
def port_scanner():
    return render_template('порт_scanner.html')

@app.route('/scan-history')
def scan_history():
    return render_template('scan_history.html')

@app.route('/vulnerability')
def vulnerability():
    return render_template('vulnerability.html')

@app.route('/traffic')
def traffic():
    return render_template('traffic.html')

@app.route('/wifi-passwords')
def wifi_passwords():
    return render_template('password.html')

@app.route('/monitor')
def network_monitor():
    monitor_data = monitor.get_monitor_data()
    return render_template('monitor.html', data=monitor_data)

@app.route('/threats')
def network_threats():
    return render_template('threats.html')

@app.route('/alerts')
def alerts():
    return render_template('send_alert.html')

@app.route('/ngrok')
def ngrok_page():
    return render_template('ngrok.html')

# API routes (unchanged, included for completeness)
@app.route('/api/alerts/send', methods=['POST'])
def send_alerts():
    try:
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body is required"
            }), 400

        emails = data.get('emails', '').strip()
        phones = data.get('phones', '').strip()
        message = data.get('message', '').strip()

        if not emails and not phones:
            return jsonify({
                "status": "error",
                "message": "At least one email address or phone number is required"
            }), 400

        if not message:
            return jsonify({
                "status": "error",
                "message": "Alert message is required"
            }), 400

        results = []

        if emails:
            email_list = [email.strip() for email in emails.replace('\n', ',').split(',') if email.strip()]
            for email in email_list:
                email_result = send_email(email, "Network Security Alert", message)
                results.append({
                    "type": "email",
                    "recipient": email,
                    "status": email_result["status"],
                    "message": email_result["message"]
                })

        if phones:
            phone_list = ','.join([phone.strip() for phone in phones.replace('\n', ',').split(',') if phone.strip()])
            sms_result = send_sms(phone_list, message[:160])
            results.append({
                "type": "sms",
                "recipient": phone_list,
                "status": sms_result["status"],
                "message": sms_result["message"]
            })

        success = any(result["status"] == "success" for result in results)
        status = "success" if success else "error"
        message = "Alerts sent successfully" if success else "Failed to send some or all alerts"

        return jsonify({
            "status": status,
            "message": message,
            "results": results
        })

    except Exception as e:
        logger.error(f"Error sending alerts: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to send alerts: {str(e)}"
        }), 500

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.json
        ip_range = data.get('ip_range', "192.168.1.0/24")
        timeout = float(data.get('timeout', 0.5))
        max_threads = int(data.get('max_threads', 200))
        
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
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        
        devices = get_all_devices()
        
        if not devices:
            return jsonify({
                "status": "no_data",
                "message": "No devices found"
            })
        
        if active_only:
            devices = [device for device in devices if device.get('status') == 'Active']
        
        devices.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
        
        if limit:
            devices = devices[:int(limit)]
        
        return jsonify({
            "status": "success",
            "data": {
                "devices": devices,
                "active_count": sum(1 for device in devices if device.get('status') == 'Active')
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
        devices = get_all_devices()
        total_devices = len(devices)
        active_devices = sum(1 for device in devices if device.get('status') == 'Active')
        
        vulnerabilities = 0
        vuln_files = list(VULNERABILITIES_DIR.glob('*.json'))
        for file in vuln_files:
            try:
                with open(file, 'r') as f:
                    vuln_data = json.load(f)
                    vulnerabilities += len(vuln_data.get('vulnerabilities', []))
            except Exception as e:
                logger.error(f"Error reading vulnerability file {file}: {str(e)}")
        
        open_ports = 0
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
        
        count = min(count, 10)
        timeout = min(timeout, 5.0)
        
        result = ping_host(ip, count, timeout)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error handling ping request: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to process ping request: {str(e)}"
        }), 500

@app.route('/api/ports/scan', methods=['POST'])
def start_port_scan():
    try:
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body is required"
            }), 400

        ip = data.get('ip')
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        port_start = int(data.get('port_start', 1))
        port_end = int(data.get('port_end', 1024))
        timeout = float(data.get('timeout', 1.0))
        max_threads = int(data.get('max_threads', 100))
        
        port_range = list(range(port_start, port_end + 1))
        
        result = scan_ports(ip, port_range, timeout, max_threads)
        
        return jsonify(result)
    except ValueError as e:
        logger.error(f"Invalid input for port scan: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Invalid input: {str(e)}"
        }), 400
    except Exception as e:
        logger.error(f"Error starting port scan: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to start port scan: {str(e)}"
        }), 500

@app.route('/api/ports/status')
def check_port_scan_status():
    try:
        ip = request.args.get('ip')
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        status = get_port_scan_status(ip)
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error checking port scan status: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to check port scan status: {str(e)}"
        }), 500

@app.route('/api/ports/results')
def get_port_scan_results():
    try:
        ip = request.args.get('ip')
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        results = get_port_results(ip)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error getting port scan results: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get port scan results: {str(e)}"
        }), 500

@app.route('/api/ports/cancel')
def cancel_port_scan():
    try:
        ip = request.args.get('ip')
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        result = cancel_scan(ip)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error cancelling port scan: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to cancel port scan: {str(e)}"
        }), 500

@app.route('/api/ports/test-connection')
def test_port_connection():
    try:
        ip = request.args.get('ip')
        port = request.args.get('port')
        
        if not ip or not port:
            return jsonify({
                "status": "error",
                "message": "IP address and port are required"
            }), 400
        
        result = test_connection(ip, int(port))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error testing connection: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to test connection: {str(e)}"
        }), 500

@app.route('/api/ports/auto-detect')
def auto_detect_port_scan():
    try:
        ip = request.args.get('ip')
        timeout = request.args.get('timeout', 0.5)
        
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        result = auto_detect_ports(ip, float(timeout))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error auto-detecting ports: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to auto-detect ports: {str(e)}"
        }), 500

@app.route('/api/vulnerability/scan', methods=['POST'])
def scan_vulnerabilities():
    try:
        data = request.json
        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body is required"
            }), 400

        ip = data.get('ip')
        if not ip:
            return jsonify({
                "status": "error",
                "message": "IP address is required"
            }), 400
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = "unknown"
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    
                    open_ports.append({
                        "port": port,
                        "service": service
                    })
            except:
                pass
        
        vulnerabilities = []
        
        if any(p["port"] == 21 for p in open_ports):
            vulnerabilities.append({
                "name": "FTP Service Exposed",
                "severity": "Medium",
                "description": "FTP service is running and accessible. This could potentially allow unauthorized access if not properly secured.",
                "recommendation": "Ensure FTP is properly configured with strong authentication. Consider using SFTP instead."
            })
        
        if any(p["port"] == 23 for p in open_ports):
            vulnerabilities.append({
                "name": "Telnet Service Exposed",
                "severity": "High",
                "description": "Telnet service is running and accessible. Telnet transmits data in cleartext, including passwords.",
                "recommendation": "Disable Telnet and use SSH instead."
            })
        
        if any(p["port"] == 80 for p in open_ports) and not any(p["port"] == 443 for p in open_ports):
            vulnerabilities.append({
                "name": "HTTP Without HTTPS",
                "severity": "Medium",
                "description": "HTTP service is running without HTTPS. Data transmitted over HTTP is not encrypted.",
                "recommendation": "Configure HTTPS with a valid SSL/TLS certificate."
            })
        
        if any(p["port"] == 3389 for p in open_ports):
            vulnerabilities.append({
                "name": "RDP Service Exposed",
                "severity": "Medium",
                "description": "Remote Desktop Protocol (RDP) service is running and accessible from the network.",
                "recommendation": "Restrict RDP access to specific IP addresses and ensure strong authentication is in place."
            })
        
        vuln_file = VULNERABILITIES_DIR / f"{ip.replace('.', '_')}.json"
        vuln_data = {
            "ip": ip,
            "timestamp": str(time.time()),
            "vulnerabilities": vulnerabilities,
            "open_ports": open_ports
        }
        
        with open(vuln_file, 'w') as f:
            json.dump(vuln_data, f)
        
        return jsonify({
            "status": "success",
            "ip": ip,
            "vulnerabilities": vulnerabilities
        })
    except Exception as e:
        logger.error(f"Error scanning vulnerabilities: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to scan vulnerabilities: {str(e)}"
        }), 500

@app.route('/api/check-admin')
def check_admin():
    try:
        is_admin = wifi_password.is_admin()
        return jsonify({
            "isAdmin": is_admin
        })
    except Exception as e:
        logger.error(f"Error checking admin status: {str(e)}")
        return jsonify({
            "isAdmin": False,
            "error": str(e)
        })

@app.route('/api/wifi/profiles')
def get_wifi_profiles():
    try:
        profiles = wifi_password.get_wifi_profiles()
        return jsonify({
            "profiles": profiles
        })
    except PermissionError:
        return jsonify({
            "error": "Administrator privileges required to access WiFi profiles"
        })
    except Exception as e:
        logger.error(f"Error getting WiFi profiles: {str(e)}")
        return jsonify({
            "error": str(e)
        })

@app.route('/api/wifi/password')
def get_wifi_password():
    try:
        profile = request.args.get('profile')
        if not profile:
            return jsonify({
                "error": "Profile name is required"
            })
        
        password_info = wifi_password.get_wifi_password(profile)
        return jsonify(password_info)
    except PermissionError:
        return jsonify({
            "error": "Administrator privileges required to access WiFi passwords"
        })
    except Exception as e:
        logger.error(f"Error getting WiFi password: {str(e)}")
        return jsonify({
            "error": str(e)
        })

@app.route('/api/wifi/current')
def get_current_wifi():
    try:
        current_wifi = wifi_password.get_current_wifi()
        if current_wifi:
            return jsonify(current_wifi)
        else:
            return jsonify({
            "error": "Not connected to WiFi or unable to detect current network"
        })
    except PermissionError:
        return jsonify({
            "error": "Administrator privileges required to access current WiFi information"
        })
    except Exception as e:
        logger.error(f"Error getting current WiFi: {str(e)}")
        return jsonify({
            "error": str(e)
        })

@app.route('/monitor/data')
def get_monitor_data():
    try:
        data = monitor.get_monitor_data()
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error getting monitor data: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/monitor/start', methods=['POST'])
def start_monitor():
    try:
        result = monitor.start_monitoring()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting monitoring: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to start monitoring: {str(e)}"
        })

@app.route('/monitor/stop', methods=['POST'])
def stop_monitor():
    try:
        result = monitor.stop_monitoring()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error stopping monitoring: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to stop monitoring: {str(e)}"
        })

@app.route('/api/threats/info')
def get_threats_info():
    try:
        interfaces = threats.get_network_interfaces()
        interface = "Wi-Fi" if "Wi-Fi" in interfaces else interfaces[0] if interfaces else None
        local_ip, local_mac = threats.get_local_ip_and_mac(interface) if interface else (None, None)
        
        gateway_ip = None
        try:
            gateways = netifaces.gateways()
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
        except:
            pass
        
        return jsonify({
            "status": "success",
            "interface": interface,
            "local_ip": local_ip,
            "local_mac": local_mac,
            "gateway_ip": gateway_ip
        })
    except Exception as e:
        logger.error(f"Error getting threats info: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/threats/status')
def get_threats_status():
    try:
        threats.simulate_threats()
        is_monitoring = threats.is_monitoring
        suspicious_ips = list(threats.suspicious_ips)
        suspicious_macs = list(threats.suspicious_macs)
        total_packets = sum(threats.ip_packet_counts.values())
        total_alerts = len(threats.alert_timestamps)
        
        formatted_ips = threats.get_formatted_suspicious_ips()
        formatted_macs = threats.get_formatted_suspicious_macs()
        recent_alerts = threats.get_formatted_alerts()
        
        return jsonify({
            "status": "success",
            "is_monitoring": is_monitoring,
            "stats": {
                "total_packets": total_packets,
                "suspicious_ips": len(suspicious_ips),
                "suspicious_macs": len(suspicious_macs),
                "total_alerts": total_alerts
            },
            "suspicious_ips": formatted_ips,
            "suspicious_macs": formatted_macs,
            "recent_alerts": recent_alerts
        })
    except Exception as e:
        logger.error(f"Error getting threats status: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/threats/start', methods=['POST'])
def start_threats_monitoring():
    try:
        result = threats.start_monitoring()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting threats monitoring: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/threats/stop', methods=['POST'])
def stop_threats_monitoring():
    try:
        result = threats.stop_monitoring()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error stopping threats monitoring: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/threats/clear-alerts', methods=['POST'])
def clear_threat_alerts():
    try:
        threats.alert_timestamps.clear()
        threats.suspicious_ips.clear()
        threats.suspicious_macs.clear()
        threats.ip_packet_counts.clear()
        threats.ip_port_activity.clear()
        
        return jsonify({
            "status": "success",
            "message": "Threat alerts cleared"
        })
    except Exception as e:
        logger.error(f"Error clearing threat alerts: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/ngrok/status')
def get_ngrok_status():
    try:
        import modules.ngrok as ngrok
        status = ngrok.get_ngrok_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting ngrok status: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "is_running": False,
            "clients": [],
            "server_info": {}
        })

@app.route('/api/ngrok/start', methods=['POST'])
def start_ngrok_server():
    try:
        import modules.ngrok as ngrok
        result = ngrok.start_ngrok_server()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting ngrok server: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to start ngrok server: {str(e)}"
        })

@app.route('/api/ngrok/stop', methods=['POST'])
def stop_ngrok_server():
    try:
        import modules.ngrok as ngrok
        result = ngrok.stop_ngrok_server()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error stopping ngrok server: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to stop ngrok server: {str(e)}"
        })

@app.route('/api/ngrok/client-example')
def get_ngrok_client_example():
    try:
        import modules.ngrok as ngrok
        code = ngrok.get_client_example()
        return code
    except Exception as e:
        logger.error(f"Error getting ngrok client example: {str(e)}")
        return "Error generating client example code."

@app.route('/api/traffic/interfaces')
def get_traffic_interfaces():
    try:
        import modules.traffic as traffic
        interfaces = traffic.get_available_interfaces()
        return jsonify(interfaces)
    except Exception as e:
        logger.error(f"Error getting traffic interfaces: {str(e)}")
        return jsonify([])

@app.route('/api/traffic/start', methods=['POST'])
def start_traffic_monitoring():
    try:
        import modules.traffic as traffic
        data = request.json
        
        interface = data.get('interface')
        capture_filter = data.get('filter', '')
        max_packets = int(data.get('max_packets', 1000))
        
        result = traffic.monitor_traffic(interface, capture_filter, max_packets)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting traffic monitoring: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/traffic/stop', methods=['POST'])
def stop_traffic_monitoring():
    try:
        import modules.traffic as traffic
        result = traffic.stop_traffic_monitor()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error stopping traffic monitoring: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/traffic/stats')
def get_traffic_stats():
    try:
        import modules.traffic as traffic
        stats = traffic.get_network_usage()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting traffic stats: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/traffic/clear', methods=['POST'])
def clear_traffic_data():
    try:
        import modules.traffic as traffic
        traffic.reset_traffic_data()
        return jsonify({
            "status": "success"
        })
    except Exception as e:
        logger.error(f"Error clearing traffic data: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/favicon.ico')
def favicon():
    favicon_path = os.path.join(app.root_path, 'static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    return '', 204

def get_mac_address(ip):
    try:
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(f'arp -a {ip}', shell=True).decode('utf-8')
            mac_matches = re.findall(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
            if mac_matches:
                return mac_matches[0]
        elif platform.system().lower() == 'linux':
            output = subprocess.check_output(f'arp -n {ip}', shell=True).decode('utf-8')
            mac_matches = re.findall(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', output)
            if mac_matches:
                return mac_matches[0]
        elif platform.system().lower() == 'darwin':
            output = subprocess.check_output(f'arp -n {ip}', shell=True).decode('utf-8')
            mac_matches = re.findall(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', output)
            if mac_matches:
                return mac_matches[0]
    except Exception as e:
        logger.error(f"Error getting MAC address for {ip}: {str(e)}")
    
    return ""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
