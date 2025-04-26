# Configuration settings for the network scanner

# Server port
PORT = 5000

# Default scan settings
DEFAULT_IP_RANGE = "192.168.1.1/24"
DEFAULT_TIMEOUT = 1  # seconds


# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5900, 8080, 8443]

# Maximum number of threads for scanning
MAX_THREADS = 50

# Cache settings
CACHE_TIMEOUT = 300  # seconds (5 minutes)

# Logging settings
LOG_LEVEL = "INFO"
LOG_FILE = "network_scanner.log"

# Data directory
DATA_DIR = "data"