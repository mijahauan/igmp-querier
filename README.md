# Simple IGMP Querier for Home Networks

A lightweight Python daemon that acts as an **IGMPv2 Querier**. 

## Why This Exists

Many "Smart Managed" switches (like TP-Link Easy Smart or Netgear Plus) support **IGMP Snooping** to prevent multicast flooding. However, they often lack an active **IGMP Querier**.

Without a Querier, the switch snoops the initial "Join" request from a client, opens the port, but then closes it a few minutes later because no "General Queries" are sent to refresh the membership. This causes multicast streams (like `ka9q-radio`) to drop out after ~260 seconds.

This daemon solves that problem by periodically sending IGMP General Queries, keeping multicast group memberships alive on your network.

## How It Works

### IGMP and Multicast Basics

**IGMP (Internet Group Management Protocol)** is used by hosts to report their multicast group memberships to neighboring routers and switches. When a host wants to receive a multicast stream, it sends an **IGMP Join** message. Switches with IGMP Snooping enabled listen to these messages to learn which ports need multicast traffic.

### The Querier Role

An **IGMP Querier** periodically sends **General Query** messages to the all-hosts multicast address (`224.0.0.1`). These queries prompt hosts to re-report their group memberships. Without periodic queries:

1. The switch's IGMP snooping table entries expire (typically after 260 seconds)
2. The switch stops forwarding multicast traffic to ports that previously requested it
3. Multicast streams appear to "drop out" even though the source is still transmitting

### Election Mechanism (RFC 2236)

When multiple queriers exist on a network, they elect a single **Master Querier** using the following rules:

1. All queriers listen for IGMP Query messages from other queriers
2. When a querier receives a query from a **lower IP address**, it backs off and becomes passive
3. The querier with the **lowest IP address** wins and becomes the Master
4. If the Master stops sending queries (timeout), other queriers will take over

This daemon implements this election logic, so you can safely run it on multiple machines for redundancy.

### Packet Structure

The daemon sends **IGMPv2 General Query** packets with:
- **Type:** `0x11` (Membership Query)
- **Max Response Time:** 100 (10 seconds)
- **Group Address:** `0.0.0.0` (General Query - all groups)
- **Checksum:** Dynamically calculated per RFC 1071

### Startup Behavior

Per RFC 2236, the daemon sends a burst of 3 rapid queries at startup (5 seconds apart) to quickly establish multicast group state, then settles into the normal query interval.

## Features

- **RFC 2236 Compliant:** Implements election logic (lowest IP wins) and startup query burst
- **Robust & Recoverable:** Automatic socket recovery, IP change detection, and listener health monitoring
- **Graceful Shutdown:** Proper signal handling (SIGTERM/SIGINT) with statistics on exit
- **Security Hardened:** Systemd service runs with minimal privileges (CAP_NET_RAW only)
- **Configurable:** CLI options for query interval, timeout, and verbose logging
- **Thread-Safe:** Proper synchronization for multi-threaded operation

## Requirements

- **Python 3.6+** (uses f-strings and type hints)
- **Linux** with raw socket support
- **CAP_NET_RAW capability** or root privileges (required for raw IGMP sockets)

No external Python packages are required—only the standard library.

## Installation

### Prerequisites

1. **Identify your network interface:**
   ```bash
   ip link show
   # or
   ip addr show
   ```
   Common names: `eth0`, `enp1s0`, `ens18`, `br0`

2. **Verify Python 3 is installed:**
   ```bash
   python3 --version
   ```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/igmp-querier.git
cd igmp-querier

# Copy the script to a system location
sudo cp igmp_querier.py /usr/local/bin/
sudo chmod +x /usr/local/bin/igmp_querier.py

# Edit the service file to specify your interface
nano igmp-querier.service
# Change 'enp1s0' to your interface name on the ExecStart line

# Install and enable the systemd service
sudo cp igmp-querier.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now igmp-querier
```

### Verify Installation

```bash
# Check service status
sudo systemctl status igmp-querier

# Watch live logs
journalctl -u igmp-querier -f
```

You should see output like:
```
Starting IGMP Querier on enp1s0 (192.168.1.10)
Query interval: 60s, Competitor timeout: 255s
[Startup] Sending 3 rapid queries...
[Listener] Election listener started.
```

### Uninstall

```bash
sudo systemctl disable --now igmp-querier
sudo rm /etc/systemd/system/igmp-querier.service
sudo rm /usr/local/bin/igmp_querier.py
sudo systemctl daemon-reload
```

## Usage

```
usage: igmp_querier.py [-h] -i INTERFACE [-q QUERY_INTERVAL] [-t TIMEOUT] [-v]

Simple IGMP Querier Daemon

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface to bind to (e.g., eth0, enp1s0)
  -q QUERY_INTERVAL, --query-interval QUERY_INTERVAL
                        Seconds between IGMP queries (default: 60)
  -t TIMEOUT, --timeout TIMEOUT
                        Seconds before assuming competitor querier is gone (default: 255)
  -v, --verbose         Enable verbose (debug) logging
```

### Examples

```bash
# Basic usage (requires root or CAP_NET_RAW)
sudo python3 /usr/local/bin/igmp_querier.py -i eth0

# Custom query interval (30 seconds) and timeout (120 seconds)
sudo python3 /usr/local/bin/igmp_querier.py -i enp1s0 -q 30 -t 120

# Verbose mode for debugging (shows each query sent)
sudo python3 /usr/local/bin/igmp_querier.py -i eth0 -v
```

### Running Multiple Instances

For high availability, you can run this daemon on multiple machines on the same LAN. They will automatically elect a Master Querier (lowest IP wins). If the Master fails, another will take over within the timeout period.

## Configuration

### Tuning Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--query-interval` | 60s | How often to send IGMP queries. RFC default is 125s, but 60s is safer for home networks. |
| `--timeout` | 255s | How long to wait before assuming a competing querier is gone. Should be ~2x the query interval plus buffer. |

### Systemd Service Customization

To customize the service (e.g., change the interface or add options), edit the service file:

```bash
sudo systemctl edit igmp-querier --full
```

Or create an override:

```bash
sudo systemctl edit igmp-querier
```

Add:
```ini
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /usr/local/bin/igmp_querier.py --interface br0 --query-interval 30 --verbose
```

## Security

The systemd service file is configured with comprehensive security hardening:

| Setting | Purpose |
|---------|---------|
| `User=nobody` | Runs as unprivileged user |
| `CapabilityBoundingSet=CAP_NET_RAW` | Only allows raw socket capability |
| `AmbientCapabilities=CAP_NET_RAW` | Grants raw socket capability to non-root user |
| `NoNewPrivileges=true` | Prevents privilege escalation |
| `ProtectSystem=strict` | Read-only access to `/usr`, `/boot`, `/efi` |
| `ProtectHome=true` | No access to `/home`, `/root`, `/run/user` |
| `PrivateTmp=true` | Isolated `/tmp` directory |
| `ProtectKernelTunables=true` | No access to `/proc/sys`, `/sys` |
| `MemoryDenyWriteExecute=true` | Prevents code injection attacks |

## Troubleshooting

### "Must run as root" Error

The daemon requires raw socket access. Either run as root or grant the capability:

```bash
# Option 1: Run as root
sudo python3 igmp_querier.py -i eth0

# Option 2: Grant capability to Python (not recommended for security)
sudo setcap cap_net_raw+ep /usr/bin/python3

# Option 3: Use the systemd service (recommended)
sudo systemctl start igmp-querier
```

### "Interface not found" Error

Verify the interface name:
```bash
ip link show
```

### Multicast Still Dropping

1. **Check the querier is running:**
   ```bash
   sudo systemctl status igmp-querier
   ```

2. **Verify queries are being sent** (requires tcpdump):
   ```bash
   sudo tcpdump -i eth0 igmp
   ```
   You should see periodic "igmp query" packets.

3. **Check your switch settings:**
   - Ensure IGMP Snooping is enabled
   - Some switches have a "Querier" setting that may conflict—disable it if this daemon is running

4. **Check for competing queriers:**
   Run with `-v` flag and look for "LOST to lower IP" messages.

## License

MIT License
