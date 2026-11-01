import socket
from datetime import datetime, timezone

def main():
    hostname = socket.gethostname()
    utc_timestamp = datetime.now(timezone.utc).isoformat()
    print(f"BUILDER_ONLINE {hostname} {utc_timestamp}")

if __name__ == "__main__":
    main()
