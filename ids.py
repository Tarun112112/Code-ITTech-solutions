"""
============================================================
 INTRUSION DETECTION SYSTEM (IDS) - Beginner Version
============================================================
LEGAL/ETHICAL NOTE:
Only monitor networks/traffic you own or have permission to
monitor. Packet sniffing on networks you don't control without
permission is illegal in most countries.

This script has TWO parts:
1. A simple Python-based IDS using Scapy (easy to run and understand)
2. Example Snort rules (the industry-standard IDS tool) + how to run them

Install: pip install scapy
Note: Sniffing requires admin/root privileges.
  Linux/Mac: sudo python3 04_intrusion_detection_system.py
  Windows: run terminal as Administrator
============================================================
"""

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time


# ============================================================
# STEP 1: TRACK CONNECTION ATTEMPTS PER IP (for port scan detection)
# ============================================================
connection_attempts = defaultdict(list)
PORT_SCAN_THRESHOLD = 10   # number of distinct ports
TIME_WINDOW = 5            # seconds


# ============================================================
# STEP 2: SIGNATURE-BASED CHECKS
# ============================================================
SUSPICIOUS_PORTS = {23: "Telnet (insecure)", 445: "SMB (common ransomware target)",
                     3389: "RDP (brute-force target)"}


def check_suspicious_port(packet):
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        if dport in SUSPICIOUS_PORTS:
            print(f"[ALERT] Traffic to suspicious port {dport} "
                  f"({SUSPICIOUS_PORTS[dport]}) from {packet[IP].src}")


def check_port_scan(packet):
    """
    Detects a possible port scan: same source IP hitting many
    different destination ports in a short time window.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dport = packet[TCP].dport
        now = time.time()

        # record this attempt
        connection_attempts[src_ip].append((dport, now))

        # drop old entries outside the time window
        connection_attempts[src_ip] = [
            (p, t) for (p, t) in connection_attempts[src_ip]
            if now - t <= TIME_WINDOW
        ]

        distinct_ports = set(p for p, t in connection_attempts[src_ip])
        if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
            print(f"[ALERT] Possible port scan detected from {src_ip} "
                  f"({len(distinct_ports)} ports in {TIME_WINDOW}s)")
            connection_attempts[src_ip] = []  # reset after alert


# ============================================================
# STEP 3: PACKET HANDLER (runs on every captured packet)
# ============================================================
def process_packet(packet):
    if packet.haslayer(IP):
        check_suspicious_port(packet)
        check_port_scan(packet)


# ============================================================
# STEP 4: START SNIFFING
# ============================================================
def start_ids(interface=None):
    print("=== SIMPLE PYTHON IDS ===")
    print("Monitoring traffic... Press Ctrl+C to stop.\n")
    sniff(iface=interface, prn=process_packet, store=False)


if __name__ == "__main__":
    # Leave interface=None to auto-select default network interface
    start_ids()


"""
============================================================
 PART 2: USING REAL SNORT (industry-standard IDS)
============================================================
Snort is a separate program you install, not a Python library.

INSTALL (Kali Linux - usually preinstalled, otherwise):
    sudo apt install snort

BASIC USAGE:
    Test config:
        sudo snort -T -c /etc/snort/snort.conf

    Run in packet-sniffing mode (just print packets):
        sudo snort -v

    Run with rule-based alerts:
        sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

EXAMPLE CUSTOM RULES (add to /etc/snort/rules/local.rules):

    # Alert on any ICMP (ping) traffic
    alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001;)

    # Alert on traffic to Telnet port (insecure protocol)
    alert tcp any any -> any 23 (msg:"Telnet Traffic Detected"; sid:1000002;)

    # Alert on possible SQL injection attempt in HTTP traffic
    alert tcp any any -> any 80 (msg:"Possible SQLi Attempt";
        content:"' OR '1'='1"; sid:1000003;)

RULE FORMAT EXPLAINED:
    alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port>
        (msg:"description"; content:"pattern to match"; sid:<unique_id>;)

After adding rules, reference local.rules in snort.conf:
    include $RULE_PATH/local.rules

Then re-run Snort with the -c flag pointing to your config file.
============================================================
"""
