# Basic Network Sniffer

A Python program to capture and analyze network traffic packets in real-time
using the [scapy](https://scapy.net/) library.

---

## Features

- **Real-time packet capture** on any network interface.
- **Protocol identification** – TCP, UDP, ICMP, and other IP protocols.
- **Per-packet details:**
  - Source IP Address
  - Destination IP Address
  - Protocol (TCP / UDP / ICMP)
  - Source Port
  - Destination Port
  - Payload excerpt (hex-encoded, first 64 bytes)
- **BPF filter support** – limit captured traffic with standard Berkeley Packet Filter expressions.
- **Graceful shutdown** – press `Ctrl+C` to stop capturing at any time.

---

## Project Structure

```
codealpha_task1_Basic-network-Sniffer/
├── network_sniffer.py   # Main sniffer script
└── README.md            # This file
```

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python      | 3.6+    |
| scapy       | latest  |

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/narendraborhade-creator/codealpha_task1_Basic-network-Sniffer.git
cd codealpha_task1_Basic-network-Sniffer
```

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate.bat     # Windows
```

### 3. Install dependencies

```bash
pip install scapy
```

> **Note (Linux/macOS):** scapy requires raw-socket access.
> Either run the script with `sudo`, or grant the `CAP_NET_RAW` capability to your Python binary:
> ```bash
> sudo setcap cap_net_raw+ep $(which python3)
> ```

> **Note (Windows):** Install [Npcap](https://npcap.com/) (choose *WinPcap API-compatible mode* during installation).

---

## Usage

```
sudo python3 network_sniffer.py [--iface INTERFACE] [--count COUNT] [--filter FILTER]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--iface INTERFACE` | Network interface to sniff on (e.g. `eth0`, `wlan0`) | auto-selected |
| `--count COUNT` | Number of packets to capture then stop; `0` = unlimited | `0` (unlimited) |
| `--filter FILTER` | BPF filter string (e.g. `tcp`, `udp port 53`, `icmp`) | none (all IP traffic) |

### Examples

Capture all IP packets indefinitely on the default interface:
```bash
sudo python3 network_sniffer.py
```

Capture 100 packets on `eth0`:
```bash
sudo python3 network_sniffer.py --iface eth0 --count 100
```

Capture only HTTP traffic:
```bash
sudo python3 network_sniffer.py --filter "tcp port 80"
```

Capture only DNS queries:
```bash
sudo python3 network_sniffer.py --filter "udp port 53"
```

Capture only ICMP (ping) traffic:
```bash
sudo python3 network_sniffer.py --filter "icmp"
```

---

## Sample Output

```
======================================================================
           Basic Network Sniffer  –  CodeAlpha Task 1
======================================================================
  Interface : auto
  Packet cap: unlimited
  BPF Filter: none (all IP traffic)
======================================================================
  Press Ctrl+C to stop capturing.

======================================================================
  Timestamp        : 2024-06-01 12:34:56
  Source IP        : 192.168.1.10
  Destination IP   : 142.250.185.46
  Protocol         : TCP
  Source Port      : 54321
  Destination Port : 443
  Payload (hex)    : 16030300280000002400...
======================================================================
  Timestamp        : 2024-06-01 12:34:57
  Source IP        : 192.168.1.1
  Destination IP   : 192.168.1.10
  Protocol         : UDP
  Source Port      : 53
  Destination Port : 51820
  Payload (hex)    : <no payload>
======================================================================
^C
[INFO] Sniffing stopped by user.
[INFO] Capture complete.
```

---

## How It Works

1. **`sniff()`** (scapy) opens a raw socket on the selected interface and passes each captured frame to the `analyze_packet()` callback.
2. **`analyze_packet()`** checks for an IP layer, then extracts IP addresses, protocol, ports (TCP/UDP), and raw payload bytes.
3. **`get_payload()`** returns the first 64 bytes of the Raw layer encoded as a hex string for safe display of arbitrary binary data.
4. A **BPF filter** (if supplied) is applied at the kernel level, so only matching packets are passed to Python – reducing CPU overhead.

---

## Disclaimer

This tool is intended for **educational and authorized network monitoring purposes only**.
Capturing network traffic without permission may be illegal in your jurisdiction.
Always obtain proper authorization before sniffing traffic on any network.

---

## License

This project was created as part of the **CodeAlpha Internship – Task 1**.
