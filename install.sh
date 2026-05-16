#!/usr/bin/env bash
# =============================================================================
# Syslog Retention and SIEM Service - Raspberry Pi 4 Installer
# =============================================================================
# Requires: Raspberry Pi OS (Bookworm/Bullseye) or any Debian-based distro
# Run as root: sudo bash install.sh
# =============================================================================

set -euo pipefail

SERVICE_NAME="syslog-siem"
SERVICE_USER="syslog-siem"
INSTALL_DIR="/opt/syslog-retention-service"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"
ENV_FILE="$INSTALL_DIR/.env"
LOG_DIR="/var/log/syslog-siem"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_PORT=8080
SYSLOG_UDP_PORT=514
SYSLOG_TCP_PORT=6514
M2_MOUNT="/mnt/syslog-data"

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

# ── Python discovery — top-level so all functions can use it ─────────────────
_find_python310() {
    for cmd in python3.13 python3.12 python3.11 python3.10; do
        if command -v "$cmd" &>/dev/null; then
            local maj min
            maj=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null)
            min=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
            if [[ "$maj" -ge 3 && "$min" -ge 10 ]]; then
                echo "$cmd"; return 0
            fi
        fi
    done
    return 1
}

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
    echo -e "${GREEN}  No credentials needed here.${NC}"
    echo -e "${GRAY}  Your admin account and API keys are set up in the web${NC}"
    echo -e "${GRAY}  console on first visit -- never written to disk.${NC}"
    echo ""

    # Auto-generate secret key
    local secret
    secret=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
             || head -c 32 /dev/urandom | xxd -p | tr -d '\n')
    ok "SECRET_KEY auto-generated"

    # Syslog ports
    echo ""
    header "-- Syslog Ports --"
    echo -e "${GRAY}  UDP 514 is the standard syslog port. TCP 6514 avoids privileged-port issues.${NC}"
    echo -e "${GRAY}  On your UDM: Settings > System > Logging > Remote Syslog.${NC}"
    local udp_port tcp_port
    udp_port=$(read_input "Syslog UDP port" "514")
    tcp_port=$(read_input "Syslog TCP port" "6514")

    # Web console
    echo ""
    header "-- Web Console --"
    local api_port api_host
    api_port=$(read_input "Web console port" "8080")
    api_host=$(read_input "Bind address (0.0.0.0 = all interfaces)" "0.0.0.0")

    # Write .env — infrastructure config only, no credentials
    mkdir -p "$INSTALL_DIR"
    cat > "$ENV_FILE" <<EOF
# Generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
# This file contains only infrastructure config (ports, paths).
# No credentials are stored here. Admin account and API keys are
# configured via the web console on first visit and stored in the
# encrypted database. SECRET_KEY is moved to the OS keystore on
# first startup and this file is no longer sensitive after that.

SECRET_KEY=${secret}

SYSLOG_UDP_PORT=${udp_port}
SYSLOG_TCP_PORT=${tcp_port}

API_HOST=${api_host}
API_PORT=${api_port}
EOF
    chmod 600 "$ENV_FILE"
    echo ""
    ok ".env saved to $ENV_FILE"

    # Store ports for rest of install
    WEB_PORT="$api_port"
    SYSLOG_UDP_PORT="$udp_port"
    SYSLOG_TCP_PORT="$tcp_port"
}

# =============================================================================
# INSTALL
# =============================================================================
# =============================================================================
# M.2 STORAGE SETUP
# =============================================================================
setup_m2_storage() {
    banner
    echo -e "${CYAN}  [ M.2 / NVMe STORAGE SETUP ]${NC}\n"

    if [[ $EUID -ne 0 ]]; then
        err "Must be run as root."
        pause; return
    fi

    # ── Detect Pi model ───────────────────────────────────────────────────────
    local pi_model=""
    if [[ -f /proc/device-tree/model ]]; then
        pi_model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "")
    fi
    echo -e "  Detected hardware: ${CYAN}${pi_model:-Unknown}${NC}\n"

    local is_pi5=false
    local is_pi4=false
    if echo "$pi_model" | grep -qi "raspberry pi 5"; then
        is_pi5=true
    elif echo "$pi_model" | grep -qi "raspberry pi 4"; then
        is_pi4=true
    fi

    # ── Explain HAT types ────────────────────────────────────────────────────
    echo -e "  ${YELLOW}Supported M.2 HATs:${NC}"
    if $is_pi5; then
        echo "  - Raspberry Pi M.2 HAT+ (official)"
        echo "  - Pimoroni NVMe Base / NVMe Base Duo"
        echo "  - Waveshare PCIe to M.2 HAT+"
        echo "  - Other PCIe NVMe HATs using the Pi 5 PCIe connector"
        echo ""
        echo -e "  ${GRAY}Pi 5 uses PCIe. The NVMe drive will appear as /dev/nvme0n1.${NC}"
    elif $is_pi4; then
        echo "  - Argon ONE M.2 / Argon NEO M.2 (USB 3.0 bridge)"
        echo "  - GeekPi / 52Pi M.2 HAT (USB 3.0)"
        echo "  - Waveshare USB 3.0 to M.2 HAT"
        echo ""
        echo -e "  ${GRAY}Pi 4 M.2 HATs use USB 3.0. The drive will appear as /dev/sda or /dev/sdb.${NC}"
    else
        echo "  - Any USB 3.0 to M.2 adapter or PCIe M.2 HAT"
    fi
    echo ""

    # ── Pi 5: PCIe / NVMe overlay ────────────────────────────────────────────
    if $is_pi5; then
        local config_file="/boot/firmware/config.txt"
        [[ ! -f "$config_file" ]] && config_file="/boot/config.txt"

        step "Checking PCIe / NVMe configuration for Pi 5"
        local pcie_enabled=false
        if grep -q "dtparam=pciex1" "$config_file" 2>/dev/null || \
           lsmod 2>/dev/null | grep -q nvme || \
           [[ -e /dev/nvme0 ]]; then
            pcie_enabled=true
            ok "PCIe / NVMe already enabled"
        else
            warn "PCIe NVMe is not yet enabled in $config_file"
            echo ""
            echo -e "  ${YELLOW}To use an NVMe HAT on the Pi 5, PCIe must be enabled.${NC}"
            echo -e "  This adds the following to $config_file:"
            echo -e "  ${GRAY}  dtparam=pciex1${NC}"
            echo -e "  ${GRAY}  dtparam=pciex1_gen=3   (optional — for Gen 3 speed)${NC}"
            echo ""
            read -rp "  Enable PCIe NVMe support now? (yes/no): " en_pcie
            if [[ "${en_pcie,,}" == "yes" || "${en_pcie,,}" == "y" ]]; then
                # Back up config
                cp "$config_file" "${config_file}.bak.$(date +%Y%m%d-%H%M%S)"
                # Add PCIe params if not present
                if ! grep -q "dtparam=pciex1" "$config_file"; then
                    echo "" >> "$config_file"
                    echo "# M.2 NVMe HAT - added by syslog-siem installer" >> "$config_file"
                    echo "dtparam=pciex1" >> "$config_file"
                    echo "dtparam=pciex1_gen=3" >> "$config_file"
                fi
                ok "PCIe NVMe enabled in $config_file"
                echo ""
                echo -e "  ${YELLOW}+------------------------------------------------+${NC}"
                echo -e "  ${YELLOW}|  A REBOOT IS REQUIRED to activate NVMe.        |${NC}"
                echo -e "  ${YELLOW}|  After rebooting, run this installer again     |${NC}"
                echo -e "  ${YELLOW}|  and select M.2 Storage Setup.                |${NC}"
                echo -e "  ${YELLOW}+------------------------------------------------+${NC}"
                echo ""
                read -rp "  Reboot now? (yes/no): " do_reboot
                if [[ "${do_reboot,,}" == "yes" || "${do_reboot,,}" == "y" ]]; then
                    reboot
                fi
                pause; return
            else
                warn "PCIe not enabled. Skipping M.2 setup."
                pause; return
            fi
        fi
    fi

    # ── Detect available drives ───────────────────────────────────────────────
    step "Scanning for available drives"
    echo ""

    # List block devices excluding the OS drive and loop/rom devices
    local os_drive
    os_drive=$(lsblk -ndo pkname "$(findmnt -n -o SOURCE /)" 2>/dev/null | head -1)
    os_drive="${os_drive:-mmcblk0}"

    echo -e "  ${GRAY}(OS is on: /dev/${os_drive})${NC}\n"

    # Build list of candidate drives
    local drives=()
    while IFS= read -r line; do
        local dev size model
        dev=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $4}')
        model=$(echo "$line" | awk '{print $3}')
        # Skip OS drive, loop, rom, zram
        [[ "$dev" == "$os_drive" ]] && continue
        [[ "$dev" == loop* || "$dev" == sr* || "$dev" == zram* ]] && continue
        drives+=("$dev  $size  $model")
    done < <(lsblk -ndo NAME,TYPE,MODEL,SIZE | grep -v "^loop\|^sr\|^zram" || true)

    if [[ ${#drives[@]} -eq 0 ]]; then
        warn "No additional drives found."
        echo ""
        if $is_pi5; then
            echo "  Troubleshooting:"
            echo "  - Verify your M.2 HAT is fully seated in the PCIe connector"
            echo "  - Check the HAT's power jumper if it has one"
            echo "  - Run: lsblk   and   dmesg | grep -i nvme"
        elif $is_pi4; then
            echo "  Troubleshooting:"
            echo "  - Verify your M.2 HAT is connected to a USB 3.0 (blue) port"
            echo "  - Run: lsblk   and   dmesg | grep -i usb"
        fi
        pause; return
    fi

    echo -e "  ${CYAN}Available drives:${NC}"
    local i=1
    for d in "${drives[@]}"; do
        echo -e "  ${WHITE}$i)${NC}  /dev/$d"
        (( i++ ))
    done
    echo ""

    local choice
    read -rp "  Select drive number [1-${#drives[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#drives[@]} )); then
        warn "Invalid selection. Cancelled."
        pause; return
    fi

    local selected_entry="${drives[$((choice-1))]}"
    local selected_dev
    selected_dev="/dev/$(echo "$selected_entry" | awk '{print $1}')"
    local selected_size
    selected_size=$(echo "$selected_entry" | awk '{print $2}')

    echo ""
    echo -e "  Selected: ${CYAN}${selected_dev}${NC}  (${selected_size})"

    # ── Format warning ────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${RED}WARNING: All data on ${selected_dev} will be ERASED.${NC}"
    echo -e "  ${RED}This operation cannot be undone.${NC}"
    echo ""
    read -rp "  Type the device name to confirm (e.g. nvme0n1 or sda): " confirm_dev
    if [[ "/dev/${confirm_dev}" != "$selected_dev" && "$confirm_dev" != "$selected_dev" ]]; then
        warn "Device name did not match. Cancelled."
        pause; return
    fi

    # ── Partition and format ──────────────────────────────────────────────────
    step "Partitioning and formatting $selected_dev"
    apt-get install -y -qq parted e2fsprogs util-linux 2>/dev/null

    # Wipe existing partition table
    wipefs -a "$selected_dev" >/dev/null 2>&1 || true

    # Create GPT with single ext4 partition
    parted -s "$selected_dev" mklabel gpt
    parted -s "$selected_dev" mkpart primary ext4 0% 100%
    sleep 1
    partprobe "$selected_dev" 2>/dev/null || true
    sleep 1

    # Determine partition device name
    local part_dev
    if [[ "$selected_dev" == *nvme* ]]; then
        part_dev="${selected_dev}p1"
    else
        part_dev="${selected_dev}1"
    fi

    # Wait for partition to appear
    local retries=0
    while [[ ! -b "$part_dev" && $retries -lt 10 ]]; do
        sleep 1
        (( retries++ ))
    done

    if [[ ! -b "$part_dev" ]]; then
        err "Partition $part_dev did not appear. Try rebooting and re-running."
        pause; return
    fi

    mkfs.ext4 -L syslog-data -q "$part_dev"
    ok "Formatted $part_dev as ext4 (label: syslog-data)"

    # ── Mount point and fstab ─────────────────────────────────────────────────
    step "Configuring persistent mount at $M2_MOUNT"
    mkdir -p "$M2_MOUNT"

    # Get UUID for stable fstab entry
    local uuid
    uuid=$(blkid -s UUID -o value "$part_dev")
    if [[ -z "$uuid" ]]; then
        err "Could not read UUID from $part_dev"
        pause; return
    fi
    ok "Drive UUID: $uuid"

    # Remove any existing entry for this mount point or UUID
    sed -i "/\s${M2_MOUNT//\//\\/}\s/d" /etc/fstab
    sed -i "/UUID=${uuid}/d" /etc/fstab

    # Add fstab entry (auto-mount at boot, ext4, sane defaults)
    echo "UUID=${uuid}  ${M2_MOUNT}  ext4  defaults,noatime,nofail  0  2" >> /etc/fstab
    ok "Added to /etc/fstab"

    mount "$M2_MOUNT"
    ok "Drive mounted at $M2_MOUNT"

    # ── Migrate existing data ─────────────────────────────────────────────────
    local db_path="$INSTALL_DIR/data"
    if [[ -d "$db_path" && -n "$(ls -A "$db_path" 2>/dev/null)" ]]; then
        step "Migrating existing database to M.2 drive"
        mkdir -p "$M2_MOUNT/data"
        cp -a "$db_path/." "$M2_MOUNT/data/"
        ok "Data migrated to $M2_MOUNT/data"
    else
        mkdir -p "$M2_MOUNT/data"
    fi

    # ── Set permissions ───────────────────────────────────────────────────────
    if id -u "$SERVICE_USER" &>/dev/null; then
        chown -R "${SERVICE_USER}:${SERVICE_USER}" "$M2_MOUNT"
    fi
    chmod 750 "$M2_MOUNT/data"
    ok "Permissions set on $M2_MOUNT"

    # ── Update DB_PATH in .env ────────────────────────────────────────────────
    step "Updating DB_PATH in .env to use M.2 drive"
    local new_db_path="$M2_MOUNT/data/syslog.db"
    if [[ -f "$ENV_FILE" ]]; then
        if grep -q "^DB_PATH=" "$ENV_FILE"; then
            sed -i "s|^DB_PATH=.*|DB_PATH=${new_db_path}|" "$ENV_FILE"
        else
            echo "DB_PATH=${new_db_path}" >> "$ENV_FILE"
        fi
        ok "DB_PATH set to $new_db_path"
    else
        warn ".env not found at $ENV_FILE — create it with option 1 (Install) first."
        warn "Then manually add: DB_PATH=${new_db_path}"
    fi

    # ── Disk info ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "${GREEN}  ============================================${NC}"
    echo -e "${GREEN}  M.2 storage ready!${NC}"
    echo -e "${GREEN}  Drive   : $selected_dev  (${selected_size})${NC}"
    echo -e "${GREEN}  Mount   : $M2_MOUNT${NC}"
    echo -e "${GREEN}  DB path : $new_db_path${NC}"
    echo -e "${GREEN}  UUID    : $uuid${NC}"
    echo -e "${GREEN}  ============================================${NC}"
    echo ""
    echo -e "${YELLOW}  Next: restart the service for the new DB path to take effect.${NC}"
    read -rp "  Restart service now? (yes/no): " do_restart
    if [[ "${do_restart,,}" == "yes" || "${do_restart,,}" == "y" ]]; then
        systemctl restart "$SERVICE_NAME" 2>/dev/null && ok "Service restarted" || warn "Service not running"
    fi
    pause
}

# =============================================================================
# M.2 DETECTION — called inline during install
# =============================================================================
_prompt_m2_during_install() {
    # Skip if DB_PATH already points somewhere non-default (re-install)
    if [[ -f "$ENV_FILE" ]]; then
        local existing_db
        existing_db=$(grep '^DB_PATH=' "$ENV_FILE" | cut -d= -f2 | tr -d ' ' || echo "")
        if [[ -n "$existing_db" && "$existing_db" != "$INSTALL_DIR/data/syslog.db" ]]; then
            ok "DB_PATH already configured: $existing_db"
            return
        fi
    fi

    # Skip if M.2 mount is already active and DB_PATH set
    if mountpoint -q "$M2_MOUNT" 2>/dev/null; then
        ok "M.2 drive already mounted at $M2_MOUNT"
        if [[ -f "$ENV_FILE" ]] && ! grep -q '^DB_PATH=' "$ENV_FILE"; then
            echo "DB_PATH=${M2_MOUNT}/data/syslog.db" >> "$ENV_FILE"
            ok "DB_PATH set to ${M2_MOUNT}/data/syslog.db"
        fi
        return
    fi

    # Detect candidate drives (non-OS block devices)
    local os_drive
    os_drive=$(lsblk -ndo pkname "$(findmnt -n -o SOURCE /)" 2>/dev/null | head -1 || echo "mmcblk0")
    local found_drives=()
    while IFS= read -r line; do
        local dev size
        dev=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        [[ "$dev" == "$os_drive" || "$dev" == loop* || "$dev" == sr* || "$dev" == zram* ]] && continue
        found_drives+=("/dev/$dev ($size)")
    done < <(lsblk -ndo NAME,SIZE,TYPE | grep " disk$" || true)

    [[ ${#found_drives[@]} -eq 0 ]] && return  # No extra drives — skip silently

    echo ""
    echo -e "${CYAN}  +--------------------------------------------------+${NC}"
    echo -e "${CYAN}  |   M.2 / NVMe Drive Detected                      |${NC}"
    echo -e "${CYAN}  +--------------------------------------------------+${NC}"
    echo ""
    for d in "${found_drives[@]}"; do
        echo -e "  Found: ${WHITE}$d${NC}"
    done
    echo ""
    echo -e "  ${YELLOW}Using an M.2/NVMe drive for the database is strongly${NC}"
    echo -e "  ${YELLOW}recommended over the SD card — faster writes and no wear.${NC}"
    echo ""
    read -rp "  Set up M.2/NVMe storage for the database now? (yes/no): " use_m2
    if [[ "${use_m2,,}" == "yes" || "${use_m2,,}" == "y" ]]; then
        setup_m2_storage
    else
        warn "Using SD card for database. Run option 8 from the main menu to set up M.2 later."
    fi
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

    # ── System packages ───────────────────────────────────────────────────────
    step "Installing system dependencies"
    apt-get update -qq
    apt-get install -y -qq \
        git ufw curl rsync libcap2-bin \
        python3 python3-pip python3-venv \
        2>/dev/null
    ok "Base packages installed"

    # ── Python 3.10+ — auto-install if system default is too old ─────────────
    step "Checking Python 3.10+"

    _find_python310() {
        for cmd in python3.13 python3.12 python3.11 python3.10; do
            if command -v "$cmd" &>/dev/null; then
                local maj min
                maj=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null)
                min=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
                if [[ "$maj" -ge 3 && "$min" -ge 10 ]]; then
                    echo "$cmd"; return 0
                fi
            fi
        done
        return 1
    }

    SYS_PYTHON=$(_find_python310 || true)

    if [[ -z "$SYS_PYTHON" ]]; then
        warn "Python 3.10+ not found. Attempting automatic installation..."
        echo ""

        # ── Try package manager first (fast path) ────────────────────────────
        local pkg_installed=false
        for pkg in python3.12 python3.11 python3.10; do
            step "Trying apt: $pkg"
            if apt-get install -y -qq "$pkg" "${pkg}-venv" 2>/dev/null; then
                ok "$pkg installed from apt"
                pkg_installed=true
                break
            fi
        done

        # ── Build from source (slow path — package manager failed) ───────────
        if ! $pkg_installed; then
            warn "Package manager does not have Python 3.10+. Building from source."
            echo ""
            echo -e "  ${YELLOW}This will take 10-20 minutes on a Raspberry Pi.${NC}"
            echo -e "  ${YELLOW}Do not interrupt the build.${NC}"
            echo ""

            # Build dependencies
            step "Installing build dependencies"
            apt-get install -y -qq \
                build-essential zlib1g-dev libncurses5-dev libgdbm-dev \
                libnss3-dev libssl-dev libsqlite3-dev libreadline-dev \
                libffi-dev libbz2-dev liblzma-dev uuid-dev tk-dev \
                wget ca-certificates
            ok "Build dependencies installed"

            local PY_VERSION="3.11.9"
            local PY_TARBALL="Python-${PY_VERSION}.tgz"
            local PY_URL="https://www.python.org/ftp/python/${PY_VERSION}/${PY_TARBALL}"
            local BUILD_DIR="/tmp/python-src-build"

            # Download
            step "Downloading Python ${PY_VERSION} source from python.org"
            rm -rf "$BUILD_DIR"
            mkdir -p "$BUILD_DIR"
            if ! wget -q --show-progress -O "${BUILD_DIR}/${PY_TARBALL}" "$PY_URL"; then
                err "Download failed. Check internet connectivity."
                err "  URL: $PY_URL"
                pause; return
            fi
            ok "Downloaded Python ${PY_VERSION}"

            # Extract
            step "Extracting source"
            tar -xzf "${BUILD_DIR}/${PY_TARBALL}" -C "$BUILD_DIR"
            ok "Extracted"

            # Configure
            # --enable-shared: needed for some Python extensions
            # --with-ensurepip=install: bundles pip
            # No --enable-optimizations: adds 2-3x build time (PGO) — not worth it on Pi
            step "Configuring (./configure)"
            local src_dir="${BUILD_DIR}/Python-${PY_VERSION}"
            cd "$src_dir"
            ./configure \
                --prefix=/usr/local \
                --enable-shared \
                --with-ensurepip=install \
                LDFLAGS="-Wl,-rpath=/usr/local/lib" \
                2>&1 | tail -5
            ok "Configured"

            # Compile — use all CPU cores, show live output so user sees progress
            local ncpus
            ncpus=$(nproc 2>/dev/null || echo 4)
            step "Compiling with $ncpus cores — grab a coffee, this takes a while..."
            if ! make -j"$ncpus" 2>&1 | grep -E "^(gcc|cc|Compiling|Building|error:)" | tail -1; then
                # make itself may have failed; check
                make -j"$ncpus" || { err "Compilation failed."; cd /; rm -rf "$BUILD_DIR"; pause; return; }
            fi
            ok "Compilation complete"

            # Install with altinstall so we don't replace the system python3 symlink
            step "Installing Python ${PY_VERSION} to /usr/local"
            make altinstall 2>&1 | grep -v "^Copying\|^Compiling"
            ldconfig 2>/dev/null || true
            cd /
            rm -rf "$BUILD_DIR"
            ok "Python ${PY_VERSION} installed at /usr/local/bin/python3.11"
        fi

        SYS_PYTHON=$(_find_python310 || true)
        if [[ -z "$SYS_PYTHON" ]]; then
            err "Python 3.10+ still not found after install attempt."
            err "Please install manually: sudo apt-get install python3.11 python3.11-venv"
            pause; return
        fi
    fi

    local py_ver
    py_ver=$("$SYS_PYTHON" --version 2>&1)
    ok "Using $SYS_PYTHON  ($py_ver)"

    # Ensure the venv module is available for the chosen Python
    local py_short
    py_short=$(basename "$SYS_PYTHON")  # e.g. python3.11
    apt-get install -y -qq "${py_short}-venv" 2>/dev/null \
        || "$SYS_PYTHON" -m ensurepip --upgrade 2>/dev/null \
        || true

    ok "Git $(git --version 2>/dev/null | awk '{print $3}' || echo 'not found')"

    # rsyslog conflict check — rsyslog binds UDP 514 by default on Debian/Pi OS
    # If we try to bind 514 too, the service crashes and restarts in a tight loop
    # which makes the Pi unresponsive.
    step "Checking for port 514 conflict (rsyslog)"
    if ss -ulnp 2>/dev/null | grep -q ":514 " && systemctl is-active --quiet rsyslog 2>/dev/null; then
        warn "rsyslog is running and has UDP port 514 bound."
        warn "If your syslog UDP port is also 514, the service will conflict and restart rapidly."
        echo ""
        echo -e "  Options:"
        echo -e "  ${CYAN}A)${NC} Disable rsyslog (recommended if this Pi is dedicated to SIEM)"
        echo -e "  ${CYAN}B)${NC} Keep rsyslog and use a different UDP port (e.g. 5514)"
        echo -e "  ${CYAN}C)${NC} Skip - I will resolve this manually"
        read -rp "  Choice [A/B/C]: " conflict_choice
        case "${conflict_choice^^}" in
            A)
                systemctl stop rsyslog
                systemctl disable rsyslog
                ok "rsyslog stopped and disabled"
                ;;
            B)
                warn "Remember to change SYSLOG_UDP_PORT in Settings after install"
                warn "and update your UDM syslog target port to match."
                ;;
            *)
                warn "Skipped. If the service fails to start, check for port conflicts with: ss -ulnp | grep 514"
                ;;
        esac
    else
        ok "No port 514 conflict detected"
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
        SYSLOG_UDP_PORT=$(grep '^SYSLOG_UDP_PORT=' "$ENV_FILE" | cut -d= -f2 | tr -d ' ' || echo "514")
        SYSLOG_TCP_PORT=$(grep '^SYSLOG_TCP_PORT=' "$ENV_FILE" | cut -d= -f2 | tr -d ' ' || echo "6514")
    fi

    # Virtual environment — always use the verified Python 3.10+ binary
    step "Creating Python virtual environment"
    if [[ ! -d "$VENV_DIR" ]]; then
        "$SYS_PYTHON" -m venv "$VENV_DIR"
        ok "Venv created at $VENV_DIR  ($(${VENV_DIR}/bin/python --version 2>&1))"
    else
        local venv_ver
        venv_ver=$("${VENV_DIR}/bin/python" --version 2>&1)
        ok "Venv already exists  ($venv_ver)"
    fi

    # Dependencies
    step "Installing Python dependencies (may take several minutes on a Pi)"
    "$PIP" install --upgrade pip --quiet --timeout 60 --retries 5
    local req_file="$INSTALL_DIR/requirements-linux.txt"
    [[ ! -f "$req_file" ]] && req_file="$INSTALL_DIR/requirements.txt"
    echo -e "  ${GRAY}Progress is shown below. Retries on connection drops are normal.${NC}"
    if ! "$PIP" install -r "$req_file" --timeout 120 --retries 10 --no-cache-dir; then
        err "Dependency installation failed. Check the output above for details."
        echo -e "  ${YELLOW}Try running manually: sudo $PIP install -r $req_file${NC}"
        pause; return
    fi
    ok "Dependencies installed"

    # Log directory
    mkdir -p "$LOG_DIR"
    ok "Log directory: $LOG_DIR"

    # M.2 storage — offer setup if an extra drive is detected
    step "Checking for M.2 / NVMe storage"
    _prompt_m2_during_install

    # Re-read DB dir in case M.2 wizard updated DB_PATH
    db_dir="$INSTALL_DIR/data"
    if [[ -f "$ENV_FILE" ]]; then
        local cfg_db2
        cfg_db2=$(grep '^DB_PATH=' "$ENV_FILE" | cut -d= -f2 | tr -d ' ' || echo "")
        [[ -n "$cfg_db2" ]] && db_dir=$(dirname "$cfg_db2")
    fi
    mkdir -p "$db_dir"
    ok "Database directory: $db_dir"

    # Dedicated service user — runs with least privilege
    step "Creating service user '$SERVICE_USER'"
    if ! id -u "$SERVICE_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --comment "Syslog SIEM service account" "$SERVICE_USER"
        ok "User '$SERVICE_USER' created"
    else
        ok "User '$SERVICE_USER' already exists"
    fi

    # Service user owns the entire install dir so git pull + pip install
    # can be run from the web GUI update feature without needing root.
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "$INSTALL_DIR" 2>/dev/null || true
    chmod 750 "$INSTALL_DIR/data" "$LOG_DIR" 2>/dev/null || true
    # .env: owner read/write only
    if [[ -f "$ENV_FILE" ]]; then
        chown "${SERVICE_USER}:${SERVICE_USER}" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
    fi
    # Keystore directory
    mkdir -p /etc/syslog-retention
    chown "${SERVICE_USER}:${SERVICE_USER}" /etc/syslog-retention
    chmod 700 /etc/syslog-retention
    ok "Permissions configured for '$SERVICE_USER'"

    # Allow service user to restart its own systemd service (needed for web-triggered updates)
    local sudoers_file="/etc/sudoers.d/${SERVICE_NAME}"
    cat > "$sudoers_file" <<SUDOEOF
# Allows the $SERVICE_USER account to restart its own service.
# Used by the web console update feature — no other sudo rights granted.
${SERVICE_USER} ALL=(root) NOPASSWD: /bin/systemctl restart ${SERVICE_NAME}
SUDOEOF
    chmod 440 "$sudoers_file"
    ok "Sudoers: '$SERVICE_USER' may restart $SERVICE_NAME"

    # Systemd service — runs as dedicated user, not root
    # AmbientCapabilities allows binding to port 514 (<1024) without root
    step "Installing systemd service"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Syslog Retention and SIEM Service
After=network.target
Wants=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON} main.py
Environment=PYTHONDONTWRITEBYTECODE=1
Restart=always
RestartSec=30
MemoryMax=512M
CPUQuota=50%
StandardOutput=append:${LOG_DIR}/service.log
StandardError=append:${LOG_DIR}/service_err.log
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=${M2_MOUNT} /etc/syslog-retention
# Allow binding to privileged ports (<1024) without root.
# AmbientCapabilities alone (without CapabilityBoundingSet or NoNewPrivileges)
# works on modern kernels. setcap on the binary is a belt-and-suspenders backup.
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    # setcap on the REAL binary (not the venv symlink) — setcap refuses symlinks
    local real_python
    real_python=$(readlink -f "$PYTHON" 2>/dev/null || echo "$PYTHON")
    if command -v setcap &>/dev/null; then
        if setcap 'cap_net_bind_service=+ep' "$real_python" 2>/dev/null; then
            ok "setcap: granted CAP_NET_BIND_SERVICE on $(basename "$real_python")"
        else
            warn "setcap failed on $real_python — AmbientCapabilities in service unit will handle port 514 binding"
        fi
    else
        warn "setcap not found — AmbientCapabilities in service unit will handle port 514 binding"
    fi

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    ok "Service enabled (starts at boot, runs as '$SERVICE_USER')"

    # Firewall
    step "Configuring firewall (ufw)"
    # SSH MUST be allowed before enabling ufw on a headless Pi.
    # ufw allow ssh covers port 22. We also detect any custom sshd port.
    ufw allow ssh comment "SSH remote management" >/dev/null 2>&1 || true
    # Detect custom SSH port — sshd_config first, then ss fallback
    # Use if/then, NOT && short-circuit: with set -e a false [[ ]] exits the script
    local ssh_port=""
    ssh_port=$(grep -iE '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || true)
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(ss -tlnp 2>/dev/null | grep -i sshd | awk '{print $4}' | rev | cut -d: -f1 | rev | head -1 || true)
    fi
    if [[ -n "$ssh_port" && "$ssh_port" != "22" ]]; then
        ufw allow "${ssh_port}/tcp" comment "SSH custom port" >/dev/null 2>&1 || true
        ok "SSH allowed on ports 22 and $ssh_port"
    else
        ok "SSH allowed on port 22"
    fi
    # Ensure sshd is enabled and running on headless systems
    systemctl enable ssh  2>/dev/null || true
    systemctl enable sshd 2>/dev/null || true
    systemctl is-active --quiet ssh  2>/dev/null || \
    systemctl is-active --quiet sshd 2>/dev/null || \
    { warn "sshd not running — attempting start"; systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true; }
    ufw allow "${SYSLOG_UDP_PORT}/udp" comment "Syslog UDP" >/dev/null 2>&1 || true
    ufw allow "${SYSLOG_TCP_PORT}/tcp" comment "Syslog TCP" >/dev/null 2>&1 || true
    ufw allow "${WEB_PORT}/tcp"        comment "SIEM Web Console" >/dev/null 2>&1 || true
    ufw --force enable >/dev/null 2>&1 || true
    ok "Firewall rules added (SSH, UDP ${SYSLOG_UDP_PORT}, TCP ${SYSLOG_TCP_PORT}, Web ${WEB_PORT})"

    # Start service — reset any prior failed state first
    step "Starting service"
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
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
    echo -e "${GREEN}  Syslog UDP  : port ${SYSLOG_UDP_PORT}${NC}"
    echo -e "${GREEN}  Syslog TCP  : port ${SYSLOG_TCP_PORT}${NC}"
    echo -e "${GREEN}  Running as  : ${SERVICE_USER} (non-root)${NC}"
    echo -e "${GREEN}  ============================================${NC}"
    echo ""
    echo -e "${YELLOW}  Next steps:${NC}"
    echo "  1. Open http://${ip}:${WEB_PORT}"
    echo "  2. The setup wizard will ask for your admin username and password"
    echo "  3. Optionally enter your Anthropic API key during setup"
    echo "  4. Point your UDM syslog to ${ip}  (UDP ${SYSLOG_UDP_PORT} / TCP ${SYSLOG_TCP_PORT})"
    echo "  5. (Optional) Set up M.2 storage via option 8 in the main menu"
    echo ""
    echo -e "${GRAY}  Credentials are stored directly in the encrypted database.${NC}"
    echo -e "${GRAY}  They are never written to .env or any config file.${NC}"
    pause
}

# =============================================================================
# UPDATE
# =============================================================================
do_update() {
    banner
    echo -e "${CYAN}  [ UPDATE ]${NC}\n"

    # Guard: service must be installed before updating
    if [[ ! -d "$INSTALL_DIR" ]]; then
        err "Service not installed — $INSTALL_DIR does not exist."
        echo -e "  ${YELLOW}Run option 1 (Install) first.${NC}"
        pause; return
    fi

    if ! command -v git &>/dev/null; then
        err "Git not installed."
        apt-get install -y -qq git 2>/dev/null && ok "Git installed" || { pause; return; }
    fi

    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
        err "No git repository found at $INSTALL_DIR."
        echo -e "  ${YELLOW}The update feature requires the service to have been installed from git clone.${NC}"
        echo -e "  ${YELLOW}Run:  git clone https://github.com/Namoh21/syslog-retention-service.git${NC}"
        echo -e "  ${YELLOW}Then: sudo bash syslog-retention-service/install.sh  and choose Install.${NC}"
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
        "$PIP" install --upgrade pip --quiet --timeout 60 --retries 5
        local req_file="$INSTALL_DIR/requirements-linux.txt"
        [[ ! -f "$req_file" ]] && req_file="$INSTALL_DIR/requirements.txt"
        echo -e "  ${GRAY}Retries on connection drops are normal on slow connections.${NC}"
        "$PIP" install -r "$req_file" --timeout 120 --retries 10 --no-cache-dir \
            && ok "Dependencies updated" \
            || warn "Some packages may not have updated — check output above"
    else
        warn "Venv not found — run Install (option 1) first, then Update."
    fi

    step "Restarting service"
    systemctl daemon-reload
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
        systemctl restart "$SERVICE_NAME"
        sleep 3
        ok "Service status: $(get_service_status)"
    else
        warn "Service not registered with systemd. Run Install first."
    fi

    ok "Update complete."

    # Re-exec the freshly pulled install.sh
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
    rm -f "/etc/sudoers.d/${SERVICE_NAME}"
    systemctl daemon-reload
    ok "Service removed"

    step "Removing firewall rules"
    # Only remove the rules this installer added — never touch SSH
    ufw delete allow "${SYSLOG_UDP_PORT}/udp" 2>/dev/null || true
    ufw delete allow "${SYSLOG_TCP_PORT}/tcp" 2>/dev/null || true
    ufw delete allow "${WEB_PORT}/tcp"         2>/dev/null || true
    ok "Firewall rules removed (SSH rule preserved)"

    read -rp "  Remove service user '$SERVICE_USER'? (yes/no): " rm_user
    if [[ "${rm_user,,}" == "yes" || "${rm_user,,}" == "y" ]]; then
        userdel "$SERVICE_USER" 2>/dev/null && ok "User '$SERVICE_USER' removed" || warn "Could not remove user"
        rm -rf /etc/syslog-retention 2>/dev/null || true
        ok "Keystore directory removed"
    fi

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
    for f in main.py requirements-linux.txt .env keystore.py; do
        if [[ -f "$INSTALL_DIR/$f" ]]; then
            echo -e "  ${GREEN}OK${NC}      $f"
        else
            echo -e "  ${RED}MISSING${NC} $f"
        fi
    done

    # Ports
    echo ""
    header "-- Port Availability --"
    for port in $WEB_PORT $SYSLOG_UDP_PORT $SYSLOG_TCP_PORT; do
        if ss -tlnup 2>/dev/null | grep -q ":${port} " || ss -ulnp 2>/dev/null | grep -q ":${port} "; then
            echo -e "  ${GREEN}LISTENING${NC}  port $port"
        else
            echo -e "  ${YELLOW}not listening${NC}  port $port"
        fi
    done

    # Firewall
    echo ""
    header "-- Firewall (ufw) --"
    ufw status 2>/dev/null | grep -E "(${WEB_PORT}|${SYSLOG_UDP_PORT}|${SYSLOG_TCP_PORT}|Status)" | sed 's/^/  /' || echo "  ufw not active"

    # Disk space
    echo ""
    header "-- Disk Space --"
    df -h "$INSTALL_DIR" 2>/dev/null | sed 's/^/  /' || true
    if mountpoint -q "$M2_MOUNT" 2>/dev/null; then
        echo ""
        echo -e "  ${GREEN}M.2 drive mounted at $M2_MOUNT:${NC}"
        df -h "$M2_MOUNT" 2>/dev/null | sed 's/^/  /' || true
    fi

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
    echo -e "${CYAN}  8. M.2 / NVMe storage setup${NC}"
    echo -e "${WHITE}  9. Exit${NC}"
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
        8) setup_m2_storage ;;
        9) exit 0 ;;
        *) warn "Invalid choice"; sleep 1 ;;
    esac
done
