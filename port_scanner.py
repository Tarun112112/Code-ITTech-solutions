"""
============================================================
 PORT SCANNER (PYTHON) - Networking Security Tool
============================================================
LEGAL/ETHICAL NOTE:
Only scan systems you own or have explicit written permission
to test. Scanning networks you don't own without permission is
illegal in most countries.

Concepts covered: sockets, TCP/IP, ports, threading
No external libraries needed - uses Python's built-in `socket`.
============================================================
"""

import socket
from datetime import datetime
import threading


# ============================================================
# STEP 1: BASIC SINGLE PORT CHECK
# ============================================================
def scan_port(target_ip, port):
    """
    Tries to open a TCP connection to a single port.
    If it succeeds, the port is OPEN. If it fails/times out, it's CLOSED.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # don't wait forever per port
        result = sock.connect_ex((target_ip, port))  # returns 0 if port is open
        sock.close()
        return result == 0
    except socket.error:
        return False


# ============================================================
# STEP 2: SCAN A RANGE OF PORTS (SINGLE-THREADED)
# ============================================================
def simple_scan(target_ip, start_port, end_port):
    print(f"\nScanning {target_ip} from port {start_port} to {end_port}")
    print("Started at:", datetime.now())

    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f"Port {port}: OPEN")
            open_ports.append(port)

    print("Finished at:", datetime.now())
    print(f"\nOpen ports found: {open_ports}")
    return open_ports


# ============================================================
# STEP 3: FASTER VERSION USING THREADING
# ============================================================
def threaded_scan(target_ip, start_port, end_port):
    print(f"\n[Threaded] Scanning {target_ip} from port {start_port} to {end_port}")
    open_ports = []
    lock = threading.Lock()

    def worker(port):
        if scan_port(target_ip, port):
            with lock:
                open_ports.append(port)
                print(f"Port {port}: OPEN")

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()  # wait for all threads to finish

    print(f"\nOpen ports found: {sorted(open_ports)}")
    return open_ports


# ============================================================
# STEP 4: COMMON PORT NAME LOOKUP (BONUS)
# ============================================================
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}


def scan_with_service_names(target_ip, start_port, end_port):
    open_ports = threaded_scan(target_ip, start_port, end_port)
    print("\n--- Service Summary ---")
    for port in sorted(open_ports):
        service = COMMON_PORTS.get(port, "Unknown")
        print(f"Port {port} ({service}): OPEN")


# ============================================================
# MAIN - RUN THE SCANNER
# ============================================================
if __name__ == "__main__":
    print("=== PYTHON PORT SCANNER ===")
    target = input("Enter target IP (use 127.0.0.1 for your own machine): ").strip()
    start = int(input("Start port (e.g. 1): "))
    end = int(input("End port (e.g. 1024): "))

    scan_with_service_names(target, start, end)
