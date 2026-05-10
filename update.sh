#!/usr/bin/env bash
# Standalone updater for the Syslog Retention and SIEM Service (Linux/Pi)
# Usage: sudo bash update.sh

set -euo pipefail

INSTALL_DIR="/opt/syslog-retention-service"
VENV_DIR="$INSTALL_DIR/.venv"
PIP="$VENV_DIR/bin/pip"
SERVICE_NAME="syslog-siem"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

step() { echo -e "\n${CYAN}  >> $*${NC}"; }
ok()   { echo -e "${GREEN}     OK: $*${NC}"; }
warn() { echo -e "${YELLOW}     WARN: $*${NC}"; }
err()  { echo -e "${RED}     ERROR: $*${NC}"; }

if [[ $EUID -ne 0 ]]; then
    err "Run as root: sudo bash update.sh"
    exit 1
fi

echo ""
echo -e "${CYAN}  Syslog Retention Service - Updater${NC}"
echo -e "${CYAN}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

step "Pulling latest code from GitHub"
cd "$INSTALL_DIR"
dirty=$(git status --porcelain 2>/dev/null || true)
if [[ -n "$dirty" ]]; then
    git stash push -m "auto-stash $(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    warn "Local changes stashed"
fi
git fetch origin
git pull origin main
ok "Code updated"

step "Updating Python dependencies"
if [[ -f "$PIP" ]]; then
    "$PIP" install --upgrade pip --quiet
    req="$INSTALL_DIR/requirements-linux.txt"
    [[ ! -f "$req" ]] && req="$INSTALL_DIR/requirements.txt"
    "$PIP" install -r "$req" --quiet
    ok "Dependencies updated"
else
    warn "Venv not found - skipping (run install.sh first)"
fi

step "Restarting service"
systemctl daemon-reload
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl restart "$SERVICE_NAME"
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Service running"
    else
        err "Service failed to start - check: journalctl -u $SERVICE_NAME -n 30"
    fi
else
    warn "Service not installed. Run: sudo bash install.sh"
fi

echo ""
ok "Update complete."
echo ""
