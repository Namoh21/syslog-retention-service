#!/usr/bin/env bash
# uninstall.sh — Namoh SIEM uninstaller
# Usage: sudo bash uninstall.sh
set -euo pipefail

INSTALL_DIR="/opt/namoh-siem"
SERVICE_NAME="namoh-siem"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR]${NC} Please run as root: sudo bash uninstall.sh"
  exit 1
fi

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║         Namoh SIEM — Uninstaller                ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "  This will stop and remove the Namoh SIEM service."
echo ""
read -rp "  Type 'yes' to confirm: " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  warn "Uninstall cancelled."
  exit 0
fi
echo ""

# ── Stop and disable systemd service ─────────────────────────────────────────
info "Stopping and disabling $SERVICE_NAME..."
systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
ok "Service stopped and disabled."

if [ -f "$SERVICE_FILE" ]; then
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  ok "Systemd unit file removed."
fi

# ── Application files ─────────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR" ]; then
  echo ""
  read -rp "  Delete application files at $INSTALL_DIR? (yes/no): " RM_APP
  if [ "$RM_APP" = "yes" ]; then
    rm -rf "$INSTALL_DIR"
    ok "Application files removed."
  else
    warn "Application files kept at $INSTALL_DIR."
  fi
fi

# ── authbind port permissions ─────────────────────────────────────────────────
echo ""
read -rp "  Remove authbind port permissions? (yes/no): " RM_AUTHBIND
if [ "$RM_AUTHBIND" = "yes" ]; then
  rm -f /etc/authbind/byport/514  2>/dev/null || true
  rm -f /etc/authbind/byport/2055 2>/dev/null || true
  ok "authbind permissions removed."
fi

# ── UFW firewall rules ────────────────────────────────────────────────────────
echo ""
read -rp "  Remove UFW firewall rules for this service? (yes/no): " RM_UFW
if [ "$RM_UFW" = "yes" ]; then
  if command -v ufw &>/dev/null; then
    # Remove rules by comment if supported, otherwise by port
    ufw delete allow comment 'Namoh SIEM web'        2>/dev/null || ufw delete allow 8080/tcp 2>/dev/null || true
    ufw delete allow comment 'Namoh SIEM syslog UDP'  2>/dev/null || ufw delete allow 514/udp  2>/dev/null || true
    ufw delete allow comment 'Namoh SIEM syslog TCP'  2>/dev/null || ufw delete allow 6514/tcp 2>/dev/null || true
    ufw delete allow comment 'Namoh SIEM NetFlow'     2>/dev/null || ufw delete allow 2055/udp 2>/dev/null || true
    ok "UFW rules removed."
  else
    warn "ufw not found — no firewall rules to remove."
  fi
fi

echo ""
echo -e "${GREEN}Uninstall complete.${NC}"
echo ""
