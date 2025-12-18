#!/bin/bash
#
# IGMP Querier Uninstallation Script
# Removes the igmp-querier daemon and systemd service
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_PATH="/usr/local/bin/igmp_querier.py"
SERVICE_PATH="/etc/systemd/system/igmp-querier.service"

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    echo_error "This script must be run as root (use sudo)"
    exit 1
fi

echo_info "Uninstalling igmp-querier..."

# Stop and disable service if running
if systemctl is-active --quiet igmp-querier 2>/dev/null; then
    echo_info "Stopping igmp-querier service..."
    systemctl stop igmp-querier
fi

if systemctl is-enabled --quiet igmp-querier 2>/dev/null; then
    echo_info "Disabling igmp-querier service..."
    systemctl disable igmp-querier
fi

# Remove service file
if [[ -f "$SERVICE_PATH" ]]; then
    echo_info "Removing $SERVICE_PATH..."
    rm -f "$SERVICE_PATH"
    systemctl daemon-reload
fi

# Remove script
if [[ -f "$INSTALL_PATH" ]]; then
    echo_info "Removing $INSTALL_PATH..."
    rm -f "$INSTALL_PATH"
fi

echo ""
echo_info "Uninstallation complete."
