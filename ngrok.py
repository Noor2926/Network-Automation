import socket
import random
import threading
from cryptography.fernet import Fernet
from pyngrok import ngrok
import requests

# === Functions ===
def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "Unavailable"

def find_open_port(start=10000, end=60000):
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
    try:
        encrypted = conn.recv(4096)
        decrypted = fernet.decrypt(encrypted).decode()
        print(f"[{addr}] 🔓 Decrypted: {decrypted}")
        reply = f"✅ Received: {decrypted}"
        conn.send(fernet.encrypt(reply.encode()))
    finally:
        conn.close()

def run_server(ip, port, fernet):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)
    print(f"🟢 Server listening on {ip}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr, fernet)).start()

# === Main Execution ===
if __name__ == "__main__":
    print("🚀 Launching Secure Ngrok Server...")

    local_ip = get_local_ip()
    public_ip = get_public_ip()
    port = find_open_port()

    key = Fernet.generate_key()
    fernet = Fernet(key)

    print(f"🔑 [SHARE SECURELY] Encryption Key: {key.decode()}")
    print(f"📶 Local IP: {local_ip}")
    print(f"🌐 Public IP: {public_ip}")
    print(f"🔌 Using Port: {port}")

    # Ngrok Tunnel
    ngrok_tunnel = ngrok.connect(addr=port, proto="tcp")
    print(f"🌍 Ngrok TCP URL (SHARE THIS): {ngrok_tunnel.public_url}")

    # Start server
    run_server(local_ip, port, fernet)

