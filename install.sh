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

# Non-interactive overrides (for sigmond and scripted installs):
#   IGMP_INTERFACE=<name>   pre-select interface, skip prompt
#   --yes                   non-interactive; auto-confirm replace if running
YES=0
for arg in "$@"; do
    case "$arg" in
        --yes|-y) YES=1 ;;
    esac
done

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

# IGMP_INTERFACE=auto: bind to the default-route interface at every START,
# not to whatever name it has at install time.  This is what an image build
# must use -- the name baked into the unit inside the build VM (ens3) is not
# the name on the machine the image lands on (ens18), and the daemon then
# fails every 5 s forever (AI6VN v3.37, 2026-09-05).  The detection below
# still runs so a host with no usable LAN fails the install loudly.
AUTO_IF=0
if [[ "$IGMP_INTERFACE" == "auto" ]]; then AUTO_IF=1; IGMP_INTERFACE=""; fi
SERVICE_IF=""

# Pre-selected via IGMP_INTERFACE env var (sigmond / scripted path)?
if [[ -n "$IGMP_INTERFACE" ]]; then
    SELECTED_IF=""
    SELECTED_IP=""
    for idx in "${!IF_LIST[@]}"; do
        if [[ "${IF_LIST[$idx]}" == "$IGMP_INTERFACE" ]]; then
            SELECTED_IF="${IF_LIST[$idx]}"
            SELECTED_IP="${IP_LIST[$idx]}"
            break
        fi
    done
    if [[ -z "$SELECTED_IF" ]]; then
        echo_error "IGMP_INTERFACE='$IGMP_INTERFACE' is not one of the detected"
        echo_error "multicast-capable interfaces with an IPv4 address."
        exit 1
    fi
    echo_info "Using pre-selected interface (IGMP_INTERFACE): $SELECTED_IF ($SELECTED_IP)"
elif [[ ${#IF_LIST[@]} -eq 1 ]]; then
    SELECTED_IF="${IF_LIST[0]}"
    SELECTED_IP="${IP_LIST[0]}"
    echo_info "Only one interface found, using: $SELECTED_IF ($SELECTED_IP)"
elif [[ $YES -eq 1 || $AUTO_IF -eq 1 ]]; then
    # Non-interactive: the IGMP querier belongs on the LAN that carries radiod's
    # multicast — the default-route interface — never a VPN/virtual one.  Pick it
    # automatically; only bail if there's genuinely no obvious LAN interface.
    DEFAULT_IF=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    SELECTED_IF=""; SELECTED_IP=""
    for idx in "${!IF_LIST[@]}"; do
        if [[ "${IF_LIST[$idx]}" == "$DEFAULT_IF" ]]; then
            SELECTED_IF="${IF_LIST[$idx]}"; SELECTED_IP="${IP_LIST[$idx]}"; break
        fi
    done
    if [[ -z "$SELECTED_IF" ]]; then
        PHYS=()
        for idx in "${!IF_LIST[@]}"; do
            case "${IF_LIST[$idx]}" in
                tailscale*|tun*|tap*|wg*|docker*|veth*|br-*|virbr*|zt*) : ;;
                *) PHYS+=("$idx") ;;
            esac
        done
        if [[ ${#PHYS[@]} -eq 1 ]]; then
            SELECTED_IF="${IF_LIST[${PHYS[0]}]}"; SELECTED_IP="${IP_LIST[${PHYS[0]}]}"
        fi
    fi
    if [[ -n "$SELECTED_IF" ]]; then
        echo_info "Auto-selected LAN interface (default route): $SELECTED_IF ($SELECTED_IP)"
    else
        echo_error "Multiple interfaces and no obvious LAN — set IGMP_INTERFACE=<name>:"
        for idx in "${!IF_LIST[@]}"; do
            echo "  - ${IF_LIST[$idx]} (${IP_LIST[$idx]})"
        done
        exit 1
    fi
else
    read -p "Select interface number [1-${#IF_LIST[@]}]: " selection
    if [[ ! "$selection" =~ ^[0-9]+$ ]] || [[ "$selection" -lt 1 ]] || [[ "$selection" -gt ${#IF_LIST[@]} ]]; then
        echo_error "Invalid selection"
        exit 1
    fi
    SELECTED_IF="${IF_LIST[$((selection-1))]}"
    SELECTED_IP="${IP_LIST[$((selection-1))]}"
fi

# Scripted installs (--yes, or IGMP_INTERFACE=auto) get a unit that says
# `--interface auto`, whichever branch above picked today's name -- including
# the single-interface case, which is exactly what an image-build VM looks like
# and exactly where a baked name goes stale.  An explicit IGMP_INTERFACE=<name>
# and interactive choices keep the literal name the operator asked for.
if [[ -z "$IGMP_INTERFACE" && ( $YES -eq 1 || $AUTO_IF -eq 1 ) ]]; then
    SERVICE_IF="auto"
fi

echo ""
echo_info "Selected interface: $SELECTED_IF ($SELECTED_IP)"

# Check if service is already running
if systemctl is-active --quiet igmp-querier 2>/dev/null; then
    echo_warn "igmp-querier service is currently running"
    if [[ $YES -eq 1 ]]; then
        echo_info "(--yes) stopping and replacing existing installation"
    else
        read -p "Stop and replace existing installation? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo_info "Installation cancelled"
            exit 0
        fi
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
sed "s/--interface enp1s0/--interface ${SERVICE_IF:-$SELECTED_IF}/" "$SCRIPT_DIR/igmp-querier.service" > "$SERVICE_PATH"
[[ -n "$SERVICE_IF" ]] && echo_info "Service binds with --interface auto (default route, resolved at each start; today: $SELECTED_IF)"

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
