#!/usr/bin/env bash
# =============================================================================
# Syslog Retention and SIEM Service - Raspberry Pi 4 Installer
# =============================================================================
# Requires: Raspberry Pi OS (Bookworm/Bullseye) or any Debian-based distro
# Run as root: sudo bash install.sh
# =============================================================================

set -euo pipefail

SERVICE_NAME="syslog-siem"
INSTALL_DIR="/opt/syslog-retention-service"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"
ENV_FILE="$INSTALL_DIR/.env"
LOG_DIR="/var/log/syslog-siem"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_PORT=8080
SYSLOG_PORT=514

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;37m'; NC='\033[0m'

step()  { echo -e "\n${CYAN}  >> $*${NC}"; }
ok()    { echo -e "${GREEN}     OK: $*${NC}"; }
warn()  { echo -e "${YELLOW}     WARN: $*${NC}"; }
err()   { echo -e "${RED}     ERROR: $*${NC}"; }
header(){ echo -e "${CYAN}  $*${NC}"; }
ask()   { printf "  %s " "$*"; }

banner() {
    clear
    echo ""
    echo -e "${CYAN}  +--------------------------------------------------+${NC}"
    echo -e "${CYAN}  |   Syslog Retention and SIEM Service  v1.1        |${NC}"
    echo -e "${CYAN}  |   Raspberry Pi Installer                         |${NC}"
    echo -e "${CYAN}  +--------------------------------------------------+${NC}"
    echo ""
}

pause() { echo ""; read -rp "  Press Enter to continue..." _; }

get_service_status() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "Running"
    elif systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "Stopped"
    else
        echo "Not installed"
    fi
}

# ── read_input helper ─────────────────────────────────────────────────────────
# Usage: read_input "Prompt text" "default" [secret]
read_input() {
    local prompt="$1"
    local default="${2:-}"
    local secret="${3:-}"
    local val
    local display

    if [[ -n "$default" ]]; then
        display="  ${prompt} [${default}] : "
    else
        display="  ${prompt} : "
    fi

    if [[ -n "$secret" ]]; then
        read -rsp "$display" val; echo ""
    else
        read -rp "$display" val
    fi

    if [[ -z "$val" && -n "$default" ]]; then
        echo "$default"
    else
        echo "$val"
    fi
}

# =============================================================================
# CONFIGURE .env
# =============================================================================
configure_env() {
    if [[ -f "$ENV_FILE" ]]; then
        ok ".env already exists - skipping wizard"
        echo -e "${GRAY}  (Use option 6 to edit it)${NC}"
        return
    fi

    echo ""
    echo -e "${YELLOW}  +--------------------------------------------------+${NC}"
    echo -e "${YELLOW}  |   Configuration Wizard                           |${NC}"
    echo -e "${YELLOW}  |   Press Enter to accept the [default value]      |${NC}"
    echo -e "${YELLOW}  +--------------------------------------------------+${NC}"
    echo ""

    # Auto-generate secret key
    local secret
    secret=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
             || head -c 32 /dev/urandom | xxd -p | tr -d '\n')
    ok "SECRET_KEY auto-generated"

    # Admin credentials
    echo ""
    header "-- Admin Account --"
    local admin_user admin_pass
    admin_user=$(read_input "Admin username" "admin")
    while true; do
        admin_pass=$(read_input "Admin password (min 8 chars)" "" secret)
        [[ ${#admin_pass} -ge 8 ]] && break
        warn "Password must be at least 8 characters."
    done

    # Anthropic API key
    echo ""
    header "-- Claude AI --"
    echo -e "${GRAY}  Your Anthropic API key is needed for AI log analysis.${NC}"
    echo -e "${GRAY}  Get one at: https://console.anthropic.com${NC}"
    echo -e "${GRAY}  (Leave blank to skip - add it later in .env)${NC}"
    local anthropic_key
    anthropic_key=$(read_input "Anthropic API key" "")

    echo ""
    echo -e "${GRAY}  Claude model options:${NC}"
    echo -e "${GRAY}    1. claude-sonnet-4-6 (recommended)${NC}"
    echo -e "${GRAY}    2. claude-opus-4-7${NC}"
    echo -e "${GRAY}    3. claude-haiku-4-5-20251001${NC}"
    local model_choice claude_model
    model_choice=$(read_input "Choose model 1-3" "1")
    case "$model_choice" in
        2) claude_model="claude-opus-4-7" ;;
        3) claude_model="claude-haiku-4-5-20251001" ;;
        *) claude_model="claude-sonnet-4-6" ;;
    esac

    # Syslog ports
    echo ""
    header "-- Syslog Ports --"
    echo -e "${GRAY}  Port 514 is the standard syslog port (root access required - OK on Pi).${NC}"
    local udp_port tcp_port
    udp_port=$(read_input "Syslog UDP port" "514")
    tcp_port=$(read_input "Syslog TCP port" "514")

    # Web console
    echo ""
    header "-- Web Console --"
    local api_port api_host
    api_port=$(read_input "Web console port" "8080")
    api_host=$(read_input "Bind address (0.0.0.0 = all interfaces)" "0.0.0.0")

    # Retention
    echo ""
    header "-- Log Retention --"
    local ret_days max_entries
    ret_days=$(read_input "Retention period in days" "90")
    max_entries=$(read_input "Maximum log entries" "5000000")

    # External API keys
    echo ""
    header "-- External API Keys (optional) --"
    echo -e "${GRAY}  Pre-shared keys for Claude Projects (comma-separated).${NC}"
    echo -e "${GRAY}  Leave blank - generate them in the web console later.${NC}"
    local ext_keys
    ext_keys=$(read_input "External API keys" "")

    # Write .env
    mkdir -p "$INSTALL_DIR"
    cat > "$ENV_FILE" <<EOF
# Generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')

SECRET_KEY=${secret}
ADMIN_USERNAME=${admin_user}
ADMIN_PASSWORD=${admin_pass}

ANTHROPIC_API_KEY=${anthropic_key}
CLAUDE_MODEL=${claude_model}

SYSLOG_UDP_PORT=${udp_port}
SYSLOG_TCP_PORT=${tcp_port}

API_HOST=${api_host}
API_PORT=${api_port}

RETENTION_DAYS=${ret_days}
MAX_LOG_ENTRIES=${max_entries}

EXTERNAL_API_KEYS=${ext_keys}
EOF
    chmod 600 "$ENV_FILE"
    echo ""
    ok ".env saved to $ENV_FILE"

    # Store ports for rest of install
    WEB_PORT="$api_port"
    SYSLOG_PORT="$udp_port"
}

# =============================================================================
# INSTALL
# =============================================================================
do_install() {
    banner
    echo -e "${GREEN}  [ INSTALL / REPAIR ]${NC}\n"

    # Root check
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root. Use: sudo bash install.sh"
        pause; return
    fi

    # System packages
    step "Updating package list and installing system dependencies"
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv git ufw curl 2>/dev/null
    ok "System packages ready"

    # Python version check
    step "Checking Python version"
    local py_ver
    py_ver=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local py_major py_minor
    py_major=$(echo "$py_ver" | cut -d. -f1)
    py_minor=$(echo "$py_ver" | cut -d. -f2)
    if [[ "$py_major" -lt 3 || ("$py_major" -eq 3 && "$py_minor" -lt 10) ]]; then
        err "Python 3.10+ required, found $py_ver"
        echo "  Run: sudo apt-get install python3.11"
        pause; return
    fi
    ok "Python $py_ver found"

    # Git check
    step "Checking Git"
    if command -v git &>/dev/null; then
        ok "Git $(git --version | awk '{print $3}')"
    else
        warn "Git not found - update feature unavailable"
    fi

    # Copy files to install dir
    step "Installing application files to $INSTALL_DIR"
    if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" ]]; then
        mkdir -p "$INSTALL_DIR"
        rsync -a --exclude='.venv' --exclude='data' --exclude='logs' \
              --exclude='__pycache__' "$SCRIPT_DIR/" "$INSTALL_DIR/" 2>/dev/null \
        || cp -r "$SCRIPT_DIR"/. "$INSTALL_DIR/"
        ok "Files copied to $INSTALL_DIR"
    else
        ok "Already running from install directory"
    fi

    # Configure .env
    step "Configuring .env"
    configure_env

    # Read ports from .env for firewall
    if [[ -f "$ENV_FILE" ]]; then
        WEB_PORT=$(grep '^API_PORT=' "$ENV_FILE" | cut -d= -f2 | tr -d ' ' || echo "8080")
        SYSLOG_PORT=$(grep '^SYSLOG_UDP_PORT=' "$ENV_FILE" | cut -d= -f2 | tr -d ' ' || echo "514")
    fi

    # Virtual environment
    step "Creating Python virtual environment"
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
        ok "Venv created at $VENV_DIR"
    else
        ok "Venv already exists"
    fi

    # Dependencies
    step "Installing Python dependencies (this may take a few minutes on a Pi)"
    "$PIP" install --upgrade pip --quiet
    local req_file="$INSTALL_DIR/requirements-linux.txt"
    [[ ! -f "$req_file" ]] && req_file="$INSTALL_DIR/requirements.txt"
    "$PIP" install -r "$req_file"
    ok "Dependencies installed"

    # Log directory
    mkdir -p "$LOG_DIR"
    ok "Log directory: $LOG_DIR"

    # Data directory
    mkdir -p "$INSTALL_DIR/data"
    ok "Data directory: $INSTALL_DIR/data"

    # Systemd service
    step "Installing systemd service"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Syslog Retention and SIEM Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON} main.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/service.log
StandardError=append:${LOG_DIR}/service_err.log

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    ok "Service enabled (starts at boot)"

    # Firewall
    step "Configuring firewall (ufw)"
    ufw allow "${SYSLOG_PORT}/udp" comment "Syslog UDP" >/dev/null 2>&1 || true
    ufw allow "${SYSLOG_PORT}/tcp" comment "Syslog TCP" >/dev/null 2>&1 || true
    ufw allow "${WEB_PORT}/tcp"    comment "SIEM Web Console" >/dev/null 2>&1 || true
    # Enable ufw non-interactively if not already active
    ufw --force enable >/dev/null 2>&1 || true
    ok "Firewall rules added"

    # Start service
    step "Starting service"
    systemctl start "$SERVICE_NAME"
    sleep 3
    local status
    status=$(get_service_status)
    if [[ "$status" == "Running" ]]; then
        ok "Service status: $status"
    else
        err "Service status: $status"
        echo -e "${YELLOW}  Check logs with option 7 (Diagnostics)${NC}"
    fi

    # Get Pi's IP
    local ip
    ip=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}  ============================================${NC}"
    echo -e "${GREEN}  Installation complete!${NC}"
    echo -e "${GREEN}  Web console : http://${ip}:${WEB_PORT}${NC}"
    echo -e "${GREEN}  Also at     : http://localhost:${WEB_PORT}${NC}"
    echo -e "${GREEN}  Syslog      : UDP/TCP port ${SYSLOG_PORT}${NC}"
    echo -e "${GREEN}  ============================================${NC}"
    echo ""
    echo -e "${YELLOW}  Next steps:${NC}"
    echo "  1. Point your UDM syslog to ${ip} on port ${SYSLOG_PORT}"
    echo "  2. Open http://${ip}:${WEB_PORT} and log in"
    echo "  3. Add ANTHROPIC_API_KEY to .env for AI analysis"
    echo "  4. Generate an API key in the web GUI for Claude Projects"
    pause
}

# =============================================================================
# UPDATE
# =============================================================================
do_update() {
    banner
    echo -e "${CYAN}  [ UPDATE ]${NC}\n"

    if ! command -v git &>/dev/null; then
        err "Git not installed. Run: sudo apt-get install git"
        pause; return
    fi

    step "Pulling latest code from GitHub"
    cd "$INSTALL_DIR"
    local dirty
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
        local req_file="$INSTALL_DIR/requirements-linux.txt"
        [[ ! -f "$req_file" ]] && req_file="$INSTALL_DIR/requirements.txt"
        "$PIP" install -r "$req_file" --quiet
        ok "Dependencies updated"
    else
        warn "Venv not found - skipping pip update (run Install first)"
    fi

    step "Restarting service"
    systemctl daemon-reload
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl restart "$SERVICE_NAME"
        sleep 3
        ok "Service status: $(get_service_status)"
    else
        warn "Service not installed. Run Install first."
    fi

    ok "Update complete."

    # Re-exec updated script
    echo -e "\n${CYAN}  Reloading updated install.sh...${NC}"
    sleep 2
    exec bash "$INSTALL_DIR/install.sh"
}

# =============================================================================
# UNINSTALL
# =============================================================================
do_uninstall() {
    banner
    echo -e "${RED}  [ UNINSTALL ]${NC}\n"
    read -rp "  Type YES to confirm: " confirm
    [[ "$confirm" != "YES" ]] && warn "Cancelled." && pause && return

    step "Stopping and disabling service"
    systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    ok "Service removed"

    step "Removing firewall rules"
    ufw delete allow "${SYSLOG_PORT}/udp" 2>/dev/null || true
    ufw delete allow "${SYSLOG_PORT}/tcp" 2>/dev/null || true
    ufw delete allow "${WEB_PORT}/tcp"    2>/dev/null || true
    ok "Firewall rules removed"

    warn "App files, data, and .env at $INSTALL_DIR were NOT deleted."
    warn "Run 'sudo rm -rf $INSTALL_DIR' to remove everything."
    pause
}

# =============================================================================
# STATUS / LOGS
# =============================================================================
show_status() {
    banner
    echo -e "${CYAN}  [ SERVICE STATUS ]${NC}\n"

    local status
    status=$(get_service_status)
    local col="$YELLOW"
    [[ "$status" == "Running" ]] && col="$GREEN"
    echo -e "  Service : ${SERVICE_NAME}"
    echo -e "  Status  : ${col}${status}${NC}"
    echo -e "  Unit    : $SERVICE_FILE"
    echo ""

    echo -e "${GRAY}  Last 20 lines of service.log:${NC}"
    echo -e "${GRAY}  ------------------------------------------${NC}"
    if [[ -f "${LOG_DIR}/service.log" ]]; then
        tail -20 "${LOG_DIR}/service.log" | sed 's/^/  /'
    else
        warn "No log file yet at ${LOG_DIR}/service.log"
    fi

    if [[ -f "${LOG_DIR}/service_err.log" ]] && [[ -s "${LOG_DIR}/service_err.log" ]]; then
        echo ""
        echo -e "${RED}  Last 10 lines of service_err.log:${NC}"
        tail -10 "${LOG_DIR}/service_err.log" | sed 's/^/  /'
    fi
    pause
}

# =============================================================================
# DIAGNOSTICS
# =============================================================================
do_diagnostics() {
    banner
    echo -e "${CYAN}  [ DIAGNOSTICS ]${NC}\n"

    # Service
    header "-- Service --"
    local status
    status=$(get_service_status)
    local col="$RED"; [[ "$status" == "Running" ]] && col="$GREEN"
    echo -e "  Status: ${col}${status}${NC}"
    systemctl status "$SERVICE_NAME" --no-pager -l 2>/dev/null | head -20 | sed 's/^/  /' || true

    # Python
    echo ""
    header "-- Python Environment --"
    if [[ -f "$PYTHON" ]]; then
        ok "Venv Python: $($PYTHON --version 2>&1)"
    else
        err "Venv Python NOT found at $PYTHON"
        warn "Run Install to create the venv."
    fi
    ok "System Python: $(python3 --version 2>&1)"

    # Key files
    echo ""
    header "-- Key Files --"
    for f in main.py windows_service.py requirements-linux.txt .env; do
        if [[ -f "$INSTALL_DIR/$f" ]]; then
            echo -e "  ${GREEN}OK${NC}      $f"
        else
            echo -e "  ${RED}MISSING${NC} $f"
        fi
    done

    # Ports
    echo ""
    header "-- Port Availability --"
    for port in $WEB_PORT $SYSLOG_PORT; do
        if ss -tlnup 2>/dev/null | grep -q ":${port} " ; then
            echo -e "  ${GREEN}LISTENING${NC}  port $port"
        else
            echo -e "  ${YELLOW}not listening${NC}  port $port"
        fi
    done

    # Firewall
    echo ""
    header "-- Firewall (ufw) --"
    ufw status 2>/dev/null | grep -E "(${WEB_PORT}|${SYSLOG_PORT}|Status)" | sed 's/^/  /' || echo "  ufw not active"

    # Disk space
    echo ""
    header "-- Disk Space --"
    df -h "$INSTALL_DIR" 2>/dev/null | sed 's/^/  /' || true

    # Memory
    echo ""
    header "-- Memory --"
    free -h 2>/dev/null | sed 's/^/  /' || true

    # Test run
    echo ""
    header "-- Test Run --"
    read -rp "  Run app directly for 20 seconds to see live output? (yes/no): " run_test
    if [[ "$run_test" == "yes" || "$run_test" == "y" ]]; then
        echo ""
        echo -e "${YELLOW}  Stopping service and starting app directly...${NC}"
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        sleep 1
        echo -e "${YELLOW}  Output (Ctrl+C to stop early):${NC}\n"
        timeout 20 "$PYTHON" "$INSTALL_DIR/main.py" 2>&1 | sed 's/^/  /' || true
        echo ""
        echo -e "${YELLOW}  Restarting service...${NC}"
        systemctl start "$SERVICE_NAME" 2>/dev/null || true
    fi
    pause
}

# =============================================================================
# EDIT .env
# =============================================================================
edit_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        warn ".env not found - running wizard first"
        configure_env
    fi
    local editor="${EDITOR:-nano}"
    command -v "$editor" &>/dev/null || editor=vi
    "$editor" "$ENV_FILE"
    echo -e "${YELLOW}  Restart the service for changes to take effect.${NC}"
    read -rp "  Restart now? (yes/no): " ans
    if [[ "$ans" == "yes" || "$ans" == "y" ]]; then
        systemctl restart "$SERVICE_NAME" 2>/dev/null && ok "Service restarted" || warn "Service not running"
    fi
    pause
}

# =============================================================================
# MAIN MENU
# =============================================================================
while true; do
    banner
    status=$(get_service_status)
    col="$YELLOW"; [[ "$status" == "Running" ]] && col="$GREEN"
    echo -e "  Service status: ${col}${status}${NC}\n"

    echo -e "${WHITE}  1. Install / Repair${NC}"
    echo -e "${WHITE}  2. Update (pull latest + restart)${NC}"
    echo -e "${WHITE}  3. Uninstall${NC}"
    echo -e "${WHITE}  4. Show web console URL${NC}"
    echo -e "${WHITE}  5. View service status and logs${NC}"
    echo -e "${WHITE}  6. Edit .env configuration${NC}"
    echo -e "${WHITE}  7. Diagnostics and test run${NC}"
    echo -e "${WHITE}  8. Exit${NC}"
    echo ""
    read -rp "  Select option: " choice

    case "$choice" in
        1) do_install ;;
        2) do_update ;;
        3) do_uninstall ;;
        4)
            ip=$(hostname -I 2>/dev/null | awk '{print $1}')
            echo ""
            echo -e "${GREEN}  Web console: http://${ip}:${WEB_PORT}${NC}"
            echo -e "${GREEN}  Also:        http://localhost:${WEB_PORT}${NC}"
            pause
            ;;
        5) show_status ;;
        6) edit_env ;;
        7) do_diagnostics ;;
        8) exit 0 ;;
        *) warn "Invalid choice"; sleep 1 ;;
    esac
done
