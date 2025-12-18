#!/usr/bin/env python3
"""
Robust IGMP Querier with Election Support
Author: Michael James Hauan (adapted for KA9Q-Radio support)
License: MIT
Description: 
    Sends periodic IGMPv2 General Queries to keep multicast streams alive 
    on switches with IGMP Snooping enabled but no active Querier.
    Implements RFC 2236 election logic (lowest IP wins).
    
    Key Features:
    - RFC 2236 compliant querier election (lowest IP wins)
    - RFC 2113 Router Alert IP option for proper IGMP routing
    - IGMPv3 query detection for election compatibility
    - Query jitter to prevent network synchronization issues
    - Automatic socket recovery and IP change detection
    - Graceful shutdown with statistics
"""

import socket
import struct
import time
import threading
import fcntl
import sys
import argparse
import signal
import logging
import random
from typing import Optional, Tuple

# --- Constants ---
IGMP_ALL_SYSTEMS = "224.0.0.1"
IGMP_TYPE_QUERY  = 0x11
IGMP_TYPE_V3_QUERY = 0x11      # Same type, but with extended header
DEFAULT_QUERY_INTERVAL = 60    # Seconds between queries (RFC default is 125, 60 is safer for home LANs)
DEFAULT_QUERIER_TIMEOUT = 255  # ~2x Interval + buffer
STARTUP_QUERY_COUNT = 3        # RFC 2236 recommends rapid queries at startup
STARTUP_QUERY_INTERVAL = 5     # Seconds between startup queries
MAX_CONSECUTIVE_ERRORS = 10    # Threshold before attempting socket recovery
QUERY_JITTER_FRACTION = 0.25   # RFC 3376: Add up to 25% jitter to query interval

# IP Header with Router Alert Option (RFC 2113)
# This is required for IGMP packets to be properly processed by routers
IP_ROUTER_ALERT_OPTION = bytes([0x94, 0x04, 0x00, 0x00])  # Router Alert, length 4, value 0

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger("igmp-querier")


class QuerierState:
    """Thread-safe state management for the querier."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._am_querier = True
        self._last_competitor_seen = 0.0
        self._my_ip = ""
        self._interface = ""
        self._running = True
        self._listener_healthy = True
        self._queries_sent = 0
        self._elections_lost = 0
    
    @property
    def am_querier(self) -> bool:
        with self._lock:
            return self._am_querier
    
    @am_querier.setter
    def am_querier(self, value: bool):
        with self._lock:
            self._am_querier = value
    
    @property
    def last_competitor_seen(self) -> float:
        with self._lock:
            return self._last_competitor_seen
    
    @last_competitor_seen.setter
    def last_competitor_seen(self, value: float):
        with self._lock:
            self._last_competitor_seen = value
    
    @property
    def my_ip(self) -> str:
        with self._lock:
            return self._my_ip
    
    @my_ip.setter
    def my_ip(self, value: str):
        with self._lock:
            self._my_ip = value
    
    @property
    def interface(self) -> str:
        with self._lock:
            return self._interface
    
    @interface.setter
    def interface(self, value: str):
        with self._lock:
            self._interface = value
    
    @property
    def running(self) -> bool:
        with self._lock:
            return self._running
    
    @running.setter
    def running(self, value: bool):
        with self._lock:
            self._running = value
    
    @property
    def listener_healthy(self) -> bool:
        with self._lock:
            return self._listener_healthy
    
    @listener_healthy.setter
    def listener_healthy(self, value: bool):
        with self._lock:
            self._listener_healthy = value
    
    def increment_queries(self):
        with self._lock:
            self._queries_sent += 1
    
    def increment_elections_lost(self):
        with self._lock:
            self._elections_lost += 1
    
    def get_stats(self) -> dict:
        with self._lock:
            return {
                "queries_sent": self._queries_sent,
                "elections_lost": self._elections_lost,
                "am_querier": self._am_querier
            }
    
    def lose_election(self, competitor_ip: str):
        """Handle losing an election to a competitor."""
        with self._lock:
            if self._am_querier:
                log.info(f"[Election] LOST to lower IP {competitor_ip}. Backing off.")
                self._elections_lost += 1
            self._am_querier = False
            self._last_competitor_seen = time.time()


# Global state instance
state = QuerierState()


def get_ip_address(ifname: str) -> Optional[str]:
    """Retrieve the IP address of the specified interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
        # Validate it's a proper unicast address
        first_octet = int(ip.split('.')[0])
        if first_octet < 1 or first_octet > 223 or first_octet == 127:
            log.error(f"Interface '{ifname}' has non-unicast IP: {ip}")
            return None
        return ip
    except OSError:
        log.error(f"Interface '{ifname}' not found or has no IPv4 address.")
        return None
    finally:
        s.close()


def ip_to_int(ip_str: str) -> int:
    """Convert dotted quad string to integer for comparison."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def calculate_checksum(data: bytes) -> int:
    """Calculate IGMP/IP checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    
    # Fold 32-bit sum to 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    return ~total & 0xFFFF


def build_igmp_query(max_resp_time: int = 100) -> bytes:
    """
    Construct an IGMPv2 General Query packet with computed checksum.
    
    Args:
        max_resp_time: Maximum response time in 1/10 second units (default 100 = 10 seconds)
    
    Returns:
        8-byte IGMP query packet ready for transmission
    """
    # IGMP Header: Type (0x11), Max Resp Time, Checksum (0 for calculation), Group (0.0.0.0)
    packet_no_checksum = struct.pack("!BBH4s", 
        IGMP_TYPE_QUERY, 
        max_resp_time, 
        0,  # Checksum placeholder
        socket.inet_aton("0.0.0.0")
    )
    
    checksum = calculate_checksum(packet_no_checksum)
    
    # Rebuild with correct checksum
    packet = struct.pack("!BBH4s",
        IGMP_TYPE_QUERY,
        max_resp_time,
        checksum,
        socket.inet_aton("0.0.0.0")
    )
    
    return packet


def calculate_query_jitter(base_interval: int) -> float:
    """
    Calculate a randomized query interval with jitter.
    
    Per RFC 3376, query intervals should include random jitter to prevent
    synchronization of multiple queriers or hosts on the network.
    
    Args:
        base_interval: The configured query interval in seconds
    
    Returns:
        Jittered interval in seconds (base_interval * [0.75, 1.0])
    """
    jitter = random.uniform(0, QUERY_JITTER_FRACTION)
    return base_interval * (1.0 - jitter)


def create_socket(ip: str) -> Optional[socket.socket]:
    """
    Create and configure the raw IGMP socket.
    
    The socket is configured with:
    - IP_HDRINCL disabled (kernel builds IP header, we add Router Alert via IP_OPTIONS)
    - Router Alert IP option (RFC 2113) for proper IGMP routing
    - Multicast loopback enabled for self-detection
    - 5 second timeout for graceful shutdown checks
    
    Args:
        ip: The source IP address to bind to
    
    Returns:
        Configured socket or None on failure
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
        
        # Bind to the specific interface IP
        sock.bind((ip, 0))
        
        # Set Multicast Interface
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
        
        # Add Router Alert option (RFC 2113) - required for proper IGMP routing
        # This tells routers to examine the packet even if not addressed to them
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, IP_ROUTER_ALERT_OPTION)
        
        # Allow us to receive our own multicast packets
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        
        # Set TTL to 1 (IGMP packets must not be forwarded beyond local network)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        
        # Set a timeout so recvfrom doesn't block forever (allows checking state.running)
        sock.settimeout(5.0)
        
        return sock
        
    except PermissionError:
        log.critical("Must run as root (required for Raw Sockets).")
        return None
    except OSError as e:
        log.error(f"Failed to create socket: {e}")
        return None


def send_query(sock: socket.socket) -> bool:
    """Construct and send an IGMPv2 General Query. Returns True on success."""
    packet = build_igmp_query()
    
    try:
        sock.sendto(packet, (IGMP_ALL_SYSTEMS, 0))
        state.increment_queries()
        log.debug(f"Sent IGMP Query as Master ({state.my_ip})")
        return True
    except OSError as e:
        log.error(f"[Sender] Error sending packet: {e}")
        return False


def parse_igmp_query(igmp_data: bytes) -> Tuple[bool, int]:
    """
    Parse an IGMP query packet and determine its version.
    
    IGMPv1: 8 bytes, max_resp_time = 0
    IGMPv2: 8 bytes, max_resp_time > 0  
    IGMPv3: 12+ bytes (has additional fields)
    
    Args:
        igmp_data: Raw IGMP packet data (after IP header)
    
    Returns:
        Tuple of (is_valid_query, igmp_version)
    """
    if len(igmp_data) < 8:
        return (False, 0)
    
    igmp_type = igmp_data[0]
    if igmp_type != IGMP_TYPE_QUERY:
        return (False, 0)
    
    max_resp_time = igmp_data[1]
    
    # IGMPv3 queries have at least 12 bytes
    if len(igmp_data) >= 12:
        return (True, 3)
    elif max_resp_time == 0:
        return (True, 1)
    else:
        return (True, 2)


def listener_thread(sock: socket.socket):
    """
    Listen for other IGMP queries to detect competitors.
    
    Implements RFC 2236 querier election:
    - When we receive a query from a lower IP, we back off
    - When we receive a query from a higher IP, we ignore it
    - Handles IGMPv1, v2, and v3 queries for election purposes
    """
    log.info("[Listener] Election listener started.")
    consecutive_errors = 0
    
    while state.running:
        try:
            # Receive packet (IP Header + IGMP Payload)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                # Normal timeout, just continue to check state.running
                continue
            
            # Validate minimum packet size (IP header minimum is 20 bytes)
            if len(data) < 20:
                continue
                
            sender_ip_str = addr[0]
            my_ip = state.my_ip
            
            # Ignore our own packets
            if sender_ip_str == my_ip:
                continue

            # Parse IP Header to find start of IGMP
            ver_ihl = data[0]
            ihl = ver_ihl & 0x0F
            ip_header_len = ihl * 4
            
            # Validate IP header length (minimum 20, maximum 60 bytes)
            if ip_header_len < 20 or ip_header_len > 60 or ip_header_len > len(data):
                log.debug(f"Invalid IP header length: {ip_header_len}")
                continue
            
            # Parse IGMP
            igmp_data = data[ip_header_len:]
            is_query, igmp_version = parse_igmp_query(igmp_data)
            
            if not is_query:
                continue
            
            # Log the query version for debugging
            log.debug(f"Received IGMPv{igmp_version} query from {sender_ip_str}")
            
            # Election logic applies to all IGMP query versions
            sender_val = ip_to_int(sender_ip_str)
            my_val = ip_to_int(my_ip)

            if sender_val < my_val:
                # They have a lower IP. They win.
                state.lose_election(sender_ip_str)
            else:
                # We have the lower IP. Log but continue as querier.
                log.debug(f"Ignoring query from higher IP {sender_ip_str}")
            
            consecutive_errors = 0  # Reset on successful packet processing

        except OSError as e:
            consecutive_errors += 1
            log.warning(f"[Listener] Socket error: {e}")
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                log.error("[Listener] Too many consecutive errors, marking unhealthy")
                state.listener_healthy = False
                return
            time.sleep(1)
        except Exception as e:
            # Log unexpected errors with traceback for debugging
            log.exception(f"[Listener] Unexpected error: {e}")
            consecutive_errors += 1
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                state.listener_healthy = False
                return
            time.sleep(1)
    
    log.info("[Listener] Shutting down.")


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    sig_name = signal.Signals(signum).name
    log.info(f"Received {sig_name}, initiating graceful shutdown...")
    state.running = False


def main():
    parser = argparse.ArgumentParser(
        description="Simple IGMP Querier Daemon",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-i", "--interface", required=True, 
                        help="Network interface to bind to (e.g., eth0, enp1s0)")
    parser.add_argument("-q", "--query-interval", type=int, default=DEFAULT_QUERY_INTERVAL,
                        help="Seconds between IGMP queries")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_QUERIER_TIMEOUT,
                        help="Seconds before assuming competitor querier is gone")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose (debug) logging")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    state.interface = args.interface
    
    # Get own IP
    ip = get_ip_address(args.interface)
    if ip is None:
        sys.exit(1)
    state.my_ip = ip
    
    log.info(f"Starting IGMP Querier on {args.interface} ({state.my_ip})")
    log.info(f"Query interval: {args.query_interval}s, Competitor timeout: {args.timeout}s")
    
    # Setup Raw Socket (Requires Root)
    sock = create_socket(state.my_ip)
    if sock is None:
        sys.exit(1)

    # Start Listener Thread (not daemon, so we can monitor it)
    listener = threading.Thread(target=listener_thread, args=(sock,), name="IGMPListener")
    listener.start()

    consecutive_send_errors = 0
    
    try:
        # RFC 2236: Send startup query burst
        log.info(f"[Startup] Sending {STARTUP_QUERY_COUNT} rapid queries...")
        for i in range(STARTUP_QUERY_COUNT):
            if not state.running:
                break
            if state.am_querier:
                if not send_query(sock):
                    consecutive_send_errors += 1
                else:
                    consecutive_send_errors = 0
            if i < STARTUP_QUERY_COUNT - 1:
                time.sleep(STARTUP_QUERY_INTERVAL)
        
        # Main Sender Loop
        while state.running:
            now = time.time()
            
            # Check listener health
            if not state.listener_healthy:
                log.warning("[Main] Listener thread unhealthy, attempting recovery...")
                sock.close()
                
                # Re-fetch IP in case it changed
                new_ip = get_ip_address(state.interface)
                if new_ip is None:
                    log.error("[Main] Cannot recover: interface has no IP")
                    time.sleep(args.query_interval)
                    continue
                
                if new_ip != state.my_ip:
                    log.info(f"[Main] IP changed from {state.my_ip} to {new_ip}")
                    state.my_ip = new_ip
                
                sock = create_socket(state.my_ip)
                if sock is None:
                    log.error("[Main] Failed to recreate socket, will retry...")
                    time.sleep(args.query_interval)
                    continue
                
                state.listener_healthy = True
                listener = threading.Thread(target=listener_thread, args=(sock,), name="IGMPListener")
                listener.start()
                log.info("[Main] Recovery successful, listener restarted")
            
            # Check if competitor has timed out
            if not state.am_querier:
                if (now - state.last_competitor_seen) > args.timeout:
                    log.info("[Election] Competitor timeout. Taking over as Master.")
                    state.am_querier = True
            
            if state.am_querier:
                if not send_query(sock):
                    consecutive_send_errors += 1
                    if consecutive_send_errors >= MAX_CONSECUTIVE_ERRORS:
                        log.warning("[Main] Too many send errors, attempting socket recovery...")
                        state.listener_healthy = False  # Trigger recovery
                else:
                    consecutive_send_errors = 0
            
            # Periodic IP check (every query interval)
            current_ip = get_ip_address(state.interface)
            if current_ip and current_ip != state.my_ip:
                log.warning(f"[Main] Interface IP changed from {state.my_ip} to {current_ip}")
                state.listener_healthy = False  # Trigger recovery
            
            # Use jittered interval to prevent synchronization (RFC 3376)
            sleep_time = calculate_query_jitter(args.query_interval)
            time.sleep(sleep_time)
    
    finally:
        # Graceful shutdown
        log.info("Shutting down...")
        state.running = False
        
        # Wait for listener thread to finish
        listener.join(timeout=10)
        if listener.is_alive():
            log.warning("Listener thread did not exit cleanly")
        
        # Close socket
        try:
            sock.close()
        except Exception:
            pass
        
        stats = state.get_stats()
        log.info(f"Final stats: {stats['queries_sent']} queries sent, {stats['elections_lost']} elections lost")
        log.info("Shutdown complete.")


if __name__ == "__main__":
    main()
