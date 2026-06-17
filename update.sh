#!/usr/bin/env bash
# update.sh — Namoh SIEM updater
# Usage: sudo bash update.sh
set -euo pipefail

INSTALL_DIR="/opt/namoh-siem"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="namoh-siem"
GIT_TOKEN_FILE="$INSTALL_DIR/.git-token"
REPO_URL="https://github.com/Namoh21/Namoh-SIEM-AISoc.git"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  error "Please run as root: sudo bash update.sh"
fi

echo ""
echo -e "${CYAN}  Namoh SIEM — Updater  ($(date '+%Y-%m-%d %H:%M:%S'))${NC}"
echo ""

# ── Guard: must be installed ─────────────────────────────────────────────────
if [ ! -d "$INSTALL_DIR/.git" ]; then
  error "No git repository found at $INSTALL_DIR. Run install.sh first."
fi

# ── Resolve GitHub token ─────────────────────────────────────────────────────
if [ -f "$GIT_TOKEN_FILE" ]; then
  GIT_PAT="$(cat "$GIT_TOKEN_FILE" | tr -d '[:space:]')"
  info "Using stored GitHub token."
else
  echo "  GitHub PAT not found at $GIT_TOKEN_FILE."
  read -rsp "  GitHub PAT: " GIT_PAT; echo ""
  if [ -z "$GIT_PAT" ]; then
    error "GitHub PAT is required. Aborting."
  fi
  printf '%s\n' "$GIT_PAT" > "$GIT_TOKEN_FILE"
  chmod 600 "$GIT_TOKEN_FILE"
fi

PULL_URL="https://${GIT_PAT}@${REPO_URL#https://}"

# ── Stop service ──────────────────────────────────────────────────────────────
info "Stopping $SERVICE_NAME..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
ok "Service stopped."

# ── Back up database ──────────────────────────────────────────────────────────
DB_FILE="$INSTALL_DIR/data/syslog.db"
if [ -f "$DB_FILE" ]; then
  BAK="${DB_FILE}.bak-$(date +%Y%m%d%H%M%S)"
  cp "$DB_FILE" "$BAK"
  ok "Database backed up to $BAK"
else
  warn "No database found at $DB_FILE — skipping backup."
fi

# ── Back up .env ─────────────────────────────────────────────────────────────
ENV_FILE="$INSTALL_DIR/.env"
if [ -f "$ENV_FILE" ]; then
  cp "$ENV_FILE" "${ENV_FILE}.bak"
  ok ".env backed up."
fi

# ── Record ORIG_HEAD for changelog ───────────────────────────────────────────
ORIG_HEAD="$(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || echo '')"

# ── git pull ─────────────────────────────────────────────────────────────────
info "Pulling latest code from GitHub..."
git config --system --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
git -C "$INSTALL_DIR" pull "$PULL_URL" main
ok "Code updated."

# ── Reinstall requirements ────────────────────────────────────────────────────
REQ_FILE="$INSTALL_DIR/requirements-linux.txt"
[ ! -f "$REQ_FILE" ] && REQ_FILE="$INSTALL_DIR/requirements.txt"
info "Reinstalling Python requirements..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$REQ_FILE" -q
ok "Requirements up to date."

# ── Restart service ───────────────────────────────────────────────────────────
info "Restarting $SERVICE_NAME..."
systemctl daemon-reload
systemctl restart "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Service is running."
else
  warn "Service may not have started. Check: journalctl -u $SERVICE_NAME -n 50"
fi

# ── Tail logs for 10 seconds ─────────────────────────────────────────────────
info "Tailing logs for 10 seconds to confirm healthy startup..."
timeout 10 journalctl -u "$SERVICE_NAME" -f --no-pager 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
VERSION="$(git -C "$INSTALL_DIR" describe --tags --always 2>/dev/null || echo 'unknown')"
echo -e "${GREEN}  Update complete!${NC}"
echo -e "  Version: ${CYAN}${VERSION}${NC}"
echo ""
if [ -n "$ORIG_HEAD" ]; then
  CHANGELOG="$(git -C "$INSTALL_DIR" log --oneline "${ORIG_HEAD}..HEAD" 2>/dev/null || true)"
  if [ -n "$CHANGELOG" ]; then
    echo "  Changes pulled:"
    echo "$CHANGELOG" | sed 's/^/    /'
    echo ""
  else
    echo "  No new commits — already up to date."
    echo ""
  fi
fi
