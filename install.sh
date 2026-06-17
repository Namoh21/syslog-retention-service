#!/usr/bin/env bash
# install.sh — Namoh SIEM install script for Ubuntu x64
# Idempotent: safe to re-run to repair or reconfigure an installation.
# Usage: sudo bash install.sh
set -euo pipefail

INSTALL_DIR="/opt/namoh-siem"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="namoh-siem"
REPO_URL="https://github.com/Namoh21/Namoh-SIEM-AISoc.git"
GIT_TOKEN_FILE="$INSTALL_DIR/.git-token"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  error "Please run as root: sudo bash install.sh"
fi

# Remember which real user invoked sudo, so service runs as that user
if [ -n "${SUDO_USER:-}" ]; then
  RUN_USER="$SUDO_USER"
else
  RUN_USER="$(whoami)"
fi

# ── OS check ──────────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *"debian"* ]]; then
    ok "OS: ${PRETTY_NAME:-unknown}"
  else
    warn "OS is not Ubuntu/Debian (detected: ${PRETTY_NAME:-unknown}). Continuing anyway."
  fi
else
  warn "Cannot detect OS. Continuing anyway."
fi

# ── Python 3.10+ ──────────────────────────────────────────────────────────────
info "Checking Python 3.10+..."
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" &>/dev/null; then
    MAJOR=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
    MINOR=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
      PYTHON_BIN="$candidate"; break
    fi
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  info "Python 3.10+ not found — installing via apt..."
  apt-get update -qq
  apt-get install -y python3 python3-pip python3-venv
  PYTHON_BIN="python3"
fi
ok "Python: $PYTHON_BIN ($("$PYTHON_BIN" --version))"

# ── System dependencies ───────────────────────────────────────────────────────
info "Installing system dependencies..."
apt-get update -qq
apt-get install -y git python3-pip python3-venv authbind ufw curl
ok "System dependencies installed."

# ── authbind for privileged ports ────────────────────────────────────────────
info "Configuring authbind for ports 514 and 2055..."
for port in 514 2055; do
  touch "/etc/authbind/byport/$port" 2>/dev/null || true
  chmod 755 "/etc/authbind/byport/$port"
  chown "$RUN_USER" "/etc/authbind/byport/$port"
done
ok "authbind configured."

# ── Clone or update repo ──────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
  info "Repository already exists at $INSTALL_DIR."
  info "Use update.sh to pull the latest code."
else
  info "Cloning repository to $INSTALL_DIR..."

  if [ -f "$GIT_TOKEN_FILE" ]; then
    GIT_PAT="$(cat "$GIT_TOKEN_FILE" | tr -d '[:space:]')"
    info "Using stored GitHub token."
  else
    echo ""
    echo "  The repository is private. A GitHub Personal Access Token (PAT) is required."
    echo "  Create one at: https://github.com/settings/tokens (needs 'repo' scope)"
    read -rsp "  GitHub PAT: " GIT_PAT; echo ""
    if [ -z "$GIT_PAT" ]; then
      error "GitHub PAT is required. Aborting."
    fi
  fi

  CLONE_URL="https://${GIT_PAT}@${REPO_URL#https://}"
  git clone "$CLONE_URL" "$INSTALL_DIR"

  # Store PAT securely — one line, chmod 600
  mkdir -p "$INSTALL_DIR"
  printf '%s\n' "$GIT_PAT" > "$GIT_TOKEN_FILE"
  chmod 600 "$GIT_TOKEN_FILE"
  chown "$RUN_USER" "$GIT_TOKEN_FILE"
  ok "Repository cloned to $INSTALL_DIR."
fi

# ── Virtualenv ────────────────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
  info "Creating Python virtualenv at $VENV_DIR..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  ok "Virtualenv created."
else
  info "Virtualenv already exists."
fi

# ── Install requirements ──────────────────────────────────────────────────────
REQ_FILE="$INSTALL_DIR/requirements-linux.txt"
[ ! -f "$REQ_FILE" ] && REQ_FILE="$INSTALL_DIR/requirements.txt"
info "Installing Python requirements..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$REQ_FILE" -q
ok "Requirements installed."

# ── Data directory ────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/data"
chown "$RUN_USER" "$INSTALL_DIR/data"
ok "Data directory ready."

# ── .env ─────────────────────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  info ".env already exists — skipping interactive setup."
  info "Edit $ENV_FILE to change settings, then restart the service."
else
  echo ""
  echo "  ============================================================"
  echo "  Interactive Configuration — press Enter to accept defaults"
  echo "  ============================================================"
  echo ""

  read -rp "  Admin username [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"

  while true; do
    read -rsp "  Admin password (min 8 chars): " ADMIN_PASS; echo ""
    [ "${#ADMIN_PASS}" -ge 8 ] && break
    warn "Password must be at least 8 characters."
  done

  read -rsp "  Anthropic API key (optional, press Enter to skip): " ANTHROPIC_KEY; echo ""

  read -rp "  API port [8080]: " API_PORT
  API_PORT="${API_PORT:-8080}"

  read -rp "  Syslog UDP port [514]: " SYSLOG_UDP_PORT
  SYSLOG_UDP_PORT="${SYSLOG_UDP_PORT:-514}"

  read -rp "  Syslog TCP port [6514]: " SYSLOG_TCP_PORT
  SYSLOG_TCP_PORT="${SYSLOG_TCP_PORT:-6514}"

  read -rp "  NetFlow port [2055]: " NETFLOW_PORT
  NETFLOW_PORT="${NETFLOW_PORT:-2055}"

  read -rp "  Log retention days [90]: " RETENTION_DAYS
  RETENTION_DAYS="${RETENTION_DAYS:-90}"

  SECRET_KEY="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"

  cat > "$ENV_FILE" <<ENVEOF
# Generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASS}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
API_PORT=${API_PORT}
SYSLOG_UDP_PORT=${SYSLOG_UDP_PORT}
SYSLOG_TCP_PORT=${SYSLOG_TCP_PORT}
NETFLOW_PORT=${NETFLOW_PORT}
RETENTION_DAYS=${RETENTION_DAYS}
SECRET_KEY=${SECRET_KEY}
ENVEOF

  chmod 600 "$ENV_FILE"
  chown "$RUN_USER" "$ENV_FILE"
  ok ".env created."
fi

# ── Read effective port values from .env ─────────────────────────────────────
_env_val() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || true; }
API_PORT_CFG="$(_env_val API_PORT)"; API_PORT_CFG="${API_PORT_CFG:-8080}"
SYSLOG_UDP_CFG="$(_env_val SYSLOG_UDP_PORT)"; SYSLOG_UDP_CFG="${SYSLOG_UDP_CFG:-514}"
SYSLOG_TCP_CFG="$(_env_val SYSLOG_TCP_PORT)"; SYSLOG_TCP_CFG="${SYSLOG_TCP_CFG:-6514}"
NETFLOW_CFG="$(_env_val NETFLOW_PORT)"; NETFLOW_CFG="${NETFLOW_CFG:-2055}"

# ── UFW firewall rules ────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
  info "Configuring UFW firewall rules..."
  ufw allow "$API_PORT_CFG/tcp"   comment 'Namoh SIEM web'        2>/dev/null || true
  ufw allow "$SYSLOG_UDP_CFG/udp" comment 'Namoh SIEM syslog UDP'  2>/dev/null || true
  ufw allow "$SYSLOG_TCP_CFG/tcp" comment 'Namoh SIEM syslog TCP'  2>/dev/null || true
  ufw allow "$NETFLOW_CFG/udp"    comment 'Namoh SIEM NetFlow'     2>/dev/null || true
  ok "UFW rules added."
else
  warn "ufw not found — skipping firewall configuration."
fi

# ── Systemd service ───────────────────────────────────────────────────────────
# Use authbind when syslog or netflow port < 1024
USE_AUTHBIND=false
for p in "$SYSLOG_UDP_CFG" "$NETFLOW_CFG"; do
  [ "$p" -lt 1024 ] 2>/dev/null && USE_AUTHBIND=true && break
done

if [ "$USE_AUTHBIND" = "true" ]; then
  EXEC_START="/usr/bin/authbind --deep ${VENV_DIR}/bin/python3 main.py"
else
  EXEC_START="${VENV_DIR}/bin/python3 main.py"
fi

info "Writing systemd service to $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<SVCEOF
[Unit]
Description=Namoh SIEM — Syslog Retention & AI Security Analysis
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${EXEC_START}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
Environment=PYTHONUNBUFFERED=1
PrivateTmp=false
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
SVCEOF

chmod 644 "$SERVICE_FILE"

# Ensure the run user owns app files (git token, venv, data, env)
chown -R "$RUN_USER" "$INSTALL_DIR/venv" "$INSTALL_DIR/data" \
  "$ENV_FILE" "$GIT_TOKEN_FILE" 2>/dev/null || true
# Allow git to work as run user (git 2.35+ ownership check)
git config --system --add safe.directory "$INSTALL_DIR" 2>/dev/null || true

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
ok "Systemd service enabled."

# ── Start the service ─────────────────────────────────────────────────────────
info "Starting $SERVICE_NAME..."
systemctl restart "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Service is running."
else
  warn "Service may not have started. Check: sudo journalctl -u $SERVICE_NAME -n 50"
fi

# ── Success banner ────────────────────────────────────────────────────────────
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost')"
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Namoh SIEM Installation Complete!            ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Web console: ${CYAN}http://${HOST_IP}:${API_PORT_CFG}${NC}"
echo -e "  Service:     sudo systemctl status ${SERVICE_NAME}"
echo -e "  Logs:        sudo journalctl -u ${SERVICE_NAME} -f"
echo -e "  Config:      ${ENV_FILE}"
echo ""
echo "  On first visit you will be prompted to create your admin account."
echo ""
