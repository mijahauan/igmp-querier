#!/bin/bash
#
# IGMP Querier Installation Script
# Installs the igmp-querier daemon as a systemd service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PATH="/usr/local/bin/igmp_querier.py"
SERVICE_PATH="/etc/systemd/system/igmp-querier.service"

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo_error "This script must be run as root (use sudo)"
    exit 1
fi

# Check for required files
if [[ ! -f "$SCRIPT_DIR/igmp_querier.py" ]]; then
    echo_error "igmp_querier.py not found in $SCRIPT_DIR"
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/igmp-querier.service" ]]; then
    echo_error "igmp-querier.service not found in $SCRIPT_DIR"
    exit 1
fi

# Detect network interfaces
echo_info "Detecting network interfaces..."
echo ""
INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')

# Build a list of interfaces with IPs
declare -a IF_LIST
declare -a IP_LIST
i=1
while IFS= read -r iface; do
    ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [[ -n "$ip_addr" ]]; then
        IF_LIST+=("$iface")
        IP_LIST+=("$ip_addr")
        echo "  $i) $iface ($ip_addr)"
        ((i++))
    fi
done <<< "$INTERFACES"

if [[ ${#IF_LIST[@]} -eq 0 ]]; then
    echo_error "No network interfaces with IPv4 addresses found"
    exit 1
fi

echo ""

# Let user select interface
if [[ ${#IF_LIST[@]} -eq 1 ]]; then
    SELECTED_IF="${IF_LIST[0]}"
    SELECTED_IP="${IP_LIST[0]}"
    echo_info "Only one interface found, using: $SELECTED_IF ($SELECTED_IP)"
else
    read -p "Select interface number [1-${#IF_LIST[@]}]: " selection
    if [[ ! "$selection" =~ ^[0-9]+$ ]] || [[ "$selection" -lt 1 ]] || [[ "$selection" -gt ${#IF_LIST[@]} ]]; then
        echo_error "Invalid selection"
        exit 1
    fi
    SELECTED_IF="${IF_LIST[$((selection-1))]}"
    SELECTED_IP="${IP_LIST[$((selection-1))]}"
fi

echo ""
echo_info "Selected interface: $SELECTED_IF ($SELECTED_IP)"

# Check if service is already running
if systemctl is-active --quiet igmp-querier 2>/dev/null; then
    echo_warn "igmp-querier service is currently running"
    read -p "Stop and replace existing installation? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo_info "Installation cancelled"
        exit 0
    fi
    echo_info "Stopping existing service..."
    systemctl stop igmp-querier
fi

# Install the script
echo_info "Installing igmp_querier.py to $INSTALL_PATH..."
cp "$SCRIPT_DIR/igmp_querier.py" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# Create service file with selected interface
echo_info "Installing systemd service..."
sed "s/--interface enp1s0/--interface $SELECTED_IF/" "$SCRIPT_DIR/igmp-querier.service" > "$SERVICE_PATH"

# Reload systemd
echo_info "Reloading systemd..."
systemctl daemon-reload

# Enable and start service
echo_info "Enabling and starting igmp-querier service..."
systemctl enable igmp-querier
systemctl start igmp-querier

# Verify it's running
sleep 2
if systemctl is-active --quiet igmp-querier; then
    echo ""
    echo_info "Installation successful!"
    echo ""
    echo "  Interface: $SELECTED_IF ($SELECTED_IP)"
    echo "  Service:   igmp-querier.service (enabled, running)"
    echo ""
    echo "Useful commands:"
    echo "  sudo systemctl status igmp-querier   # Check status"
    echo "  sudo journalctl -u igmp-querier -f   # View logs"
    echo "  sudo systemctl restart igmp-querier  # Restart"
    echo "  sudo systemctl stop igmp-querier     # Stop"
    echo ""
else
    echo_error "Service failed to start. Check logs with:"
    echo "  sudo journalctl -u igmp-querier -n 50"
    exit 1
fi
