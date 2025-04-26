import socket
import random
import threading
import time
import logging
from cryptography.fernet import Fernet
from pyngrok import ngrok
import requests
import json
from pathlib import Path
import io
import sys
from threading import Lock

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ngrok")

# Global variables
ngrok_tunnel = None
server_socket = None
is_running = False
encryption_key = None
fernet = None
clients = []
status_lock = threading.Lock()
DATA_DIR = Path("data")
NGROK_DATA_FILE = DATA_DIR / "ngrok_data.json"

# Console output capture
console_output = []
console_lock = Lock()

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception as e:
        logger.error(f"Error getting local IP: {str(e)}")
        return "127.0.0.1"

def get_public_ip():
    """Get the public IP address of the machine."""
    try:
        return requests.get("https://api.ipify.org").text
    except Exception as e:
        logger.error(f"Error getting public IP: {str(e)}")
        return "Unavailable"

def find_open_port(start=10000, end=60000):
    """Find an open port in the given range."""
    for _ in range(100):
        port = random.randint(start, end)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except:
                continue
    raise Exception("❌ No available port found.")

def handle_client(conn, addr, fernet):
    """Handle a client connection."""
    try:
        encrypted = conn.recv(4096)
        decrypted = fernet.decrypt(encrypted).decode()
        log_message = f"[{addr}] 🔓 Decrypted: {decrypted}"
        print(log_message)
        add_console_output(log_message)
        
        # Add to clients list
        with status_lock:
            client_info = {
                "ip": addr[0],
                "port": addr[1],
                "message": decrypted,
                "timestamp": time.time()
            }
            clients.append(client_info)
            # Keep only the last 100 clients
            if len(clients) > 100:
                clients.pop(0)
        
        reply = f"✅ Received: {decrypted}"
        conn.send(fernet.encrypt(reply.encode()))
    except Exception as e:
        error_msg = f"Error handling client {addr}: {str(e)}"
        logger.error(error_msg)
        add_console_output(error_msg)
    finally:
        conn.close()

def run_server(ip, port, fernet):
    """Run the server to accept connections."""
    global server_socket, is_running
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    server_socket.settimeout(1.0)  # Set timeout for accept() to allow clean shutdown
    
    log_message = f"🟢 Server listening on {ip}:{port}"
    print(log_message)
    add_console_output(log_message)
    
    while is_running:
        try:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr, fernet)).start()
        except socket.timeout:
            continue
        except Exception as e:
            error_msg = f"Error accepting connection: {str(e)}"
            logger.error(error_msg)
            add_console_output(error_msg)
            if not is_running:
                break
    
    log_message = "Server stopped"
    print(log_message)
    add_console_output(log_message)

def add_console_output(message):
    """Add a message to the console output."""
    with console_lock:
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        console_output.append(f"[{timestamp}] {message}")
        # Keep only the last 100 messages
        if len(console_output) > 100:
            console_output.pop(0)

def get_console_output():
    """Get the console output."""
    with console_lock:
        return console_output.copy()

def clear_console_output():
    """Clear the console output."""
    with console_lock:
        console_output.clear()

def start_ngrok_server():
    """Start the ngrok server."""
    global ngrok_tunnel, encryption_key, fernet, is_running
    
    with status_lock:
        if is_running:
            return {
                "status": "error",
                "message": "Ngrok server is already running"
            }
        
        is_running = True
    
    try:
        # Clear previous console output
        clear_console_output()
        
        add_console_output("🚀 Launching Secure Ngrok Server...")
        
        local_ip = get_local_ip()
        add_console_output(f"📶 Local IP: {local_ip}")
        
        public_ip = get_public_ip()
        add_console_output(f"🌐 Public IP: {public_ip}")
        
        port = find_open_port()
        add_console_output(f"🔌 Using Port: {port}")
        
        # Generate encryption key
        encryption_key = Fernet.generate_key()
        fernet = Fernet(encryption_key)
        add_console_output(f"🔑 [SHARE SECURELY] Encryption Key: {encryption_key.decode()}")
        
        # Start ngrok tunnel
        ngrok_tunnel = ngrok.connect(addr=port, proto="tcp")
        add_console_output(f"🌍 Ngrok TCP URL (SHARE THIS): {ngrok_tunnel.public_url}")
        
        # Start server in a separate thread
        server_thread = threading.Thread(target=run_server, args=(local_ip, port, fernet))
        server_thread.daemon = True
        server_thread.start()
        
        # Save server info
        server_info = {
            "local_ip": local_ip,
            "public_ip": public_ip,
            "port": port,
            "encryption_key": encryption_key.decode(),
            "ngrok_url": ngrok_tunnel.public_url,
            "start_time": time.time()
        }
        
        save_ngrok_data(server_info)
        
        return {
            "status": "success",
            "message": "Ngrok server started successfully",
            "data": server_info,
            "console_output": get_console_output()
        }
    
    except Exception as e:
        error_msg = f"Error starting ngrok server: {str(e)}"
        logger.error(error_msg)
        add_console_output(error_msg)
        
        with status_lock:
            is_running = False
        
        return {
            "status": "error",
            "message": f"Failed to start ngrok server: {str(e)}",
            "console_output": get_console_output()
        }

def stop_ngrok_server():
    """Stop the ngrok server."""
    global ngrok_tunnel, server_socket, is_running
    
    with status_lock:
        if not is_running:
            return {
                "status": "error",
                "message": "Ngrok server is not running"
            }
        
        is_running = False
    
    try:
        add_console_output("Stopping Ngrok server...")
        
        # Close ngrok tunnel
        if ngrok_tunnel:
            ngrok.disconnect(ngrok_tunnel.public_url)
            ngrok_tunnel = None
            add_console_output("Ngrok tunnel disconnected")
        
        # Close server socket
        if server_socket:
            server_socket.close()
            server_socket = None
            add_console_output("Server socket closed")
        
        add_console_output("Ngrok server stopped successfully")
        
        return {
            "status": "success",
            "message": "Ngrok server stopped successfully",
            "console_output": get_console_output()
        }
    
    except Exception as e:
        error_msg = f"Error stopping ngrok server: {str(e)}"
        logger.error(error_msg)
        add_console_output(error_msg)
        
        return {
            "status": "error",
            "message": f"Failed to stop ngrok server: {str(e)}",
            "console_output": get_console_output()
        }

def get_ngrok_status():
    """Get the current status of the ngrok server."""
    with status_lock:
        status = {
            "is_running": is_running,
            "clients": clients.copy(),
            "server_info": {},
            "console_output": get_console_output()
        }
    
    try:
        if is_running and ngrok_tunnel:
            status["server_info"] = {
                "local_ip": get_local_ip(),
                "public_ip": get_public_ip(),
                "port": server_socket.getsockname()[1] if server_socket else None,
                "ngrok_url": ngrok_tunnel.public_url,
                "encryption_key": encryption_key.decode() if encryption_key else None
            }
    except Exception as e:
        error_msg = f"Error getting ngrok status: {str(e)}"
        logger.error(error_msg)
        add_console_output(error_msg)
    
    return status

def save_ngrok_data(server_info):
    """Save ngrok data to file."""
    try:
        data = {
            "timestamp": time.time(),
            "server_info": server_info,
            "clients": clients
        }
        
        with NGROK_DATA_FILE.open('w') as f:
            json.dump(data, f, indent=2)
        
        logger.debug("Ngrok data saved")
    except Exception as e:
        logger.error(f"Error saving ngrok data: {str(e)}")

def get_ngrok_data():
    """Get current ngrok data."""
    try:
        status = get_ngrok_status()
        
        return {
            "status": "success",
            "is_running": status["is_running"],
            "server_info": status["server_info"],
            "clients": status["clients"],
            "console_output": status["console_output"]
        }
    except Exception as e:
        logger.error(f"Error getting ngrok data: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

def get_client_example():
    """Get example client code for connecting to the server."""
    if not is_running or not encryption_key:
        return "Server not running. Start the server first to get client code."
    
    python_code = f"""
import socket
from cryptography.fernet import Fernet

# Server details
server_address = "{ngrok_tunnel.public_url.replace('tcp://', '')}"
host, port_str = server_address.split(':')
port = int(port_str)

# Encryption key (keep this secret!)
key = b"{encryption_key.decode()}"
fernet = Fernet(key)

# Create a socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))

# Send an encrypted message
message = "Hello from the client!"
encrypted_message = fernet.encrypt(message.encode())
client.send(encrypted_message)

# Receive and decrypt the response
encrypted_response = client.recv(4096)
decrypted_response = fernet.decrypt(encrypted_response).decode()
print(f"Server response: {{decrypted_response}}")

# Close the connection
client.close()
"""
    return python_code
