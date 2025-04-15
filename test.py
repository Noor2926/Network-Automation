import paramiko

def ssh_router_reset(ip, credentials):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 
                   username=credentials['user'], 
                   password=credentials['pass'],  # Fixed typo from 'passed' to 'pass'
                   timeout=10)
        
        stdin, stdout, stderr = ssh.exec_command('reset factory')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        ssh.close()
        
        if error:
            print(f"Error: {error}")
        else:
            print(f"Success: {output}")
            
        return output or "No output"
        
    except Exception as e:
        print(f"Connection failed: {str(e)}")
        return None

# Example usage:
if __name__ == "__main__":
    router_credentials = {
        'user': 'admin',
        'pass': '25800'  # Change this
    }
    result = ssh_router_reset('192.168.1.1', router_credentials)  # Change IP
    print("Final result:", result)