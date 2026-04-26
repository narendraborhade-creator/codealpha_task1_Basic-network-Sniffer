#!/usr/bin/env python3
"""
Basic Network Sniffer
=====================
A Python program to capture and analyze network traffic packets in real-time
using the scapy library.

Features:
    - Captures live network packets on a specified interface.
    - Extracts and displays source/destination IP addresses.
    - Identifies the transport-layer protocol (TCP, UDP, ICMP).
    - Shows source and destination ports (where applicable).
    - Displays a truncated hex-decoded payload for each packet.

Usage:
    Run with root / administrator privileges:
        sudo python3 network_sniffer.py [--iface INTERFACE] [--count COUNT] [--filter FILTER]

Requirements:
    - Python 3.6+
    - scapy  (pip install scapy)
"""

import argparse
import sys
from datetime import datetime

# scapy is the core library used for packet sniffing and analysis.
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("[ERROR] scapy is not installed. Run:  pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum number of payload bytes to display per packet (keeps output readable).
MAX_PAYLOAD_DISPLAY = 64

# Protocol number → human-readable name mapping for IP-layer protocols.
PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}


# ---------------------------------------------------------------------------
# Packet analysis
# ---------------------------------------------------------------------------

def get_payload(packet) -> str:
    """
    Extract and return a truncated, printable representation of the packet
    payload (Raw layer).

    Parameters
    ----------
    packet : scapy packet
        The captured packet object.

    Returns
    -------
    str
        A hex-encoded string of up to MAX_PAYLOAD_DISPLAY bytes, or
        '<no payload>' if the Raw layer is absent.
    """
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        # Truncate and encode as hex so non-printable bytes are still visible.
        truncated = raw_data[:MAX_PAYLOAD_DISPLAY]
        hex_str = truncated.hex()
        suffix = "..." if len(raw_data) > MAX_PAYLOAD_DISPLAY else ""
        return hex_str + suffix
    return "<no payload>"


def analyze_packet(packet) -> None:
    """
    Callback invoked by scapy for every captured packet.

    Extracts and prints:
        - Timestamp
        - Source IP address
        - Destination IP address
        - Protocol
        - Source port (TCP/UDP only)
        - Destination port (TCP/UDP only)
        - Payload excerpt

    Parameters
    ----------
    packet : scapy packet
        The captured packet object passed by scapy's sniff() function.
    """
    # Only process packets that have an IP layer; skip non-IP frames (ARP, etc.)
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    proto_id = ip_layer.proto
    protocol = PROTOCOL_MAP.get(proto_id, f"OTHER({proto_id})")

    # Extract port information only for TCP and UDP packets.
    src_port = dst_port = "N/A"
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    payload = get_payload(packet)

    # -----------------------------------------------------------------------
    # Display the packet summary to stdout.
    # -----------------------------------------------------------------------
    print("=" * 70)
    print(f"  Timestamp        : {timestamp}")
    print(f"  Source IP        : {src_ip}")
    print(f"  Destination IP   : {dst_ip}")
    print(f"  Protocol         : {protocol}")
    print(f"  Source Port      : {src_port}")
    print(f"  Destination Port : {dst_port}")
    print(f"  Payload (hex)    : {payload}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed argument values.
    """
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer – capture and analyze network packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 network_sniffer.py\n"
            "  sudo python3 network_sniffer.py --iface eth0 --count 50\n"
            "  sudo python3 network_sniffer.py --filter 'tcp port 80'\n"
        ),
    )
    parser.add_argument(
        "--iface",
        default=None,
        help=(
            "Network interface to sniff on (e.g. eth0, wlan0). "
            "Defaults to scapy's auto-selected interface."
        ),
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help=(
            "Number of packets to capture before stopping. "
            "0 (default) means capture indefinitely until Ctrl+C."
        ),
    )
    parser.add_argument(
        "--filter",
        default=None,
        dest="bpf_filter",
        help=(
            "BPF filter string to limit captured traffic "
            "(e.g. 'tcp', 'udp port 53', 'icmp'). "
            "Defaults to capturing all IP traffic."
        ),
    )
    return parser.parse_args()


def main() -> None:
    """
    Main function: parse arguments, print a startup banner, and start sniffing.
    """
    args = parse_arguments()

    # ------------------------------------------------------------------
    # Print startup banner
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("           Basic Network Sniffer  –  CodeAlpha Task 1")
    print("=" * 70)
    print(f"  Interface : {args.iface or 'auto'}")
    print(f"  Packet cap: {args.count if args.count > 0 else 'unlimited'}")
    print(f"  BPF Filter: {args.bpf_filter or 'none (all IP traffic)'}")
    print("=" * 70)
    print("  Press Ctrl+C to stop capturing.\n")

    try:
        # scapy's sniff() is the core capture function.
        #   prn      – callback called for each captured packet.
        #   iface    – network interface to listen on (None = default).
        #   count    – stop after this many packets (0 = infinite).
        #   filter   – BPF filter applied at the kernel level for efficiency.
        #   store    – False keeps memory usage low by not buffering packets.
        sniff(
            prn=analyze_packet,
            iface=args.iface,
            count=args.count,
            filter=args.bpf_filter,
            store=False,
        )
    except PermissionError:
        print(
            "\n[ERROR] Insufficient privileges.\n"
            "        Run the script with root/administrator rights:\n"
            "            sudo python3 network_sniffer.py"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        # Graceful exit on Ctrl+C
        print("\n[INFO] Sniffing stopped by user.")
    except Exception as exc:  # noqa: BLE001
        print(f"\n[ERROR] Unexpected error: {exc}")
        sys.exit(1)

    print("[INFO] Capture complete.")


if __name__ == "__main__":
    main()
