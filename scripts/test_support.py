"""Port allocation for isolated verification processes."""
import socket


def allocate_ports(count):
    held = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(sock)
            sock.bind(("127.0.0.1", 0))
        return tuple(sock.getsockname()[1] for sock in held)
    finally:
        for sock in held:
            sock.close()
