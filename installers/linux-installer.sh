#!/usr/bin/env bash
# =============================================================================
#  Wazuh Browser Privacy Monitor — Linux Installer
#  Author  : Ram Kumar G (IT Fortress)
#  Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)
#
#  Installs:
#    - Collector script  → /opt/browser-privacy-monitor/
#    - Config file       → /root/.browser-privacy-monitor/
#    - Log file          → /root/.browser-privacy-monitor/browser_privacy.log
#    - systemd service   → /etc/systemd/system/browser-privacy-monitor.service
#    - Wazuh localfile   → appended to /var/ossec/etc/ossec.conf
#
#  Usage:
#    sudo bash linux-installer.sh
#    sudo bash linux-installer.sh --interval 300
#    sudo bash linux-installer.sh --uninstall
# =============================================================================
set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/browser-privacy-monitor"
DATA_DIR="/root/.browser-privacy-monitor"
LOG_FILE="$DATA_DIR/browser_privacy.log"
CONFIG_FILE="$DATA_DIR/.browser_privacy_config.json"
SERVICE_NAME="browser-privacy-monitor"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_NAME="browser-privacy-monitor.py"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
SCAN_INTERVAL=300

COLLECTOR_URL="https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/collector/browser-privacy-monitor.py"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────────────
UNINSTALL=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval) SCAN_INTERVAL="$2"; shift 2 ;;
    --uninstall) UNINSTALL=true; shift ;;
    *) shift ;;
  esac
done

# ── Uninstall path ────────────────────────────────────────────────────────────
if $UNINSTALL; then
  info "Uninstalling $SERVICE_NAME..."
  systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f  "$SERVICE_FILE"
  rm -rf "$INSTALL_DIR"
  systemctl daemon-reload
  success "Uninstalled. Data dir $DATA_DIR kept for log retention."
  exit 0
fi

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash linux-installer.sh"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Wazuh Browser Privacy Monitor — Linux Installer v1.0.0 ║${NC}"
echo -e "${BOLD}║  IT Fortress by Ram Kumar G                              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Python check ──────────────────────────────────────────────────────
info "Step 1/6 — Checking Python 3..."
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
[[ -z "$PYTHON" ]] && error "Python 3 not found. Install with: apt install python3"
PY_VER=$("$PYTHON" --version 2>&1)
success "Found: $PY_VER → $PYTHON"

# ── Step 2: Create directories ───────────────────────────────────────────────
info "Step 2/6 — Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
success "Install dir: $INSTALL_DIR"
success "Data dir:    $DATA_DIR"

# ── Step 3: Download/copy collector ──────────────────────────────────────────
info "Step 3/6 — Installing collector script..."
SCRIPT_DST="$INSTALL_DIR/$SCRIPT_NAME"

# Try local copy first (if script is in same directory as installer)
SCRIPT_LOCAL="$(dirname "$0")/../collector/$SCRIPT_NAME"
if [[ -f "$SCRIPT_LOCAL" ]]; then
  cp "$SCRIPT_LOCAL" "$SCRIPT_DST"
  success "Installed from local copy."
elif command -v curl &>/dev/null; then
  curl -sSL "$COLLECTOR_URL" -o "$SCRIPT_DST"
  success "Downloaded from GitHub."
elif command -v wget &>/dev/null; then
  wget -qO "$SCRIPT_DST" "$COLLECTOR_URL"
  success "Downloaded from GitHub (wget)."
else
  error "Cannot install collector: curl/wget not found and no local copy."
fi
chmod 700 "$SCRIPT_DST"

# ── Step 4: Write config ──────────────────────────────────────────────────────
info "Step 4/6 — Writing config (interval: ${SCAN_INTERVAL}s)..."
cat > "$CONFIG_FILE" <<CONFIG
{
  "scan_interval_seconds": ${SCAN_INTERVAL},
  "version": "1.0.0"
}
CONFIG
chmod 600 "$CONFIG_FILE"
success "Config: $CONFIG_FILE"

# ── Step 5: Create systemd service ───────────────────────────────────────────
info "Step 5/6 — Creating systemd service..."
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Wazuh Browser Privacy Monitor - Phase 3
Documentation=https://github.com/Ramkumar2545/wazuh-browser-privacy-monitor
After=network.target

[Service]
Type=simple
ExecStart=${PYTHON} ${SCRIPT_DST}
WorkingDirectory=${DATA_DIR}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=browser-privacy-monitor

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable  "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
  success "Service running: $SERVICE_NAME"
else
  warn "Service may have failed. Check: journalctl -u $SERVICE_NAME -n 20"
fi

# ── Step 6: Wazuh localfile config ────────────────────────────────────────────
info "Step 6/6 — Configuring Wazuh agent localfile..."
LOCALFILE_BLOCK="
  <!-- Browser Privacy Monitor Phase 3 - Privacy-Safe Telemetry -->
  <localfile>
    <log_format>json</log_format>
    <location>${LOG_FILE}</location>
    <label key=\"integration\">browser-privacy-monitor</label>
  </localfile>"

if [[ -f "$OSSEC_CONF" ]]; then
  if grep -q "browser-privacy-monitor" "$OSSEC_CONF"; then
    warn "Wazuh localfile already configured. Skipping."
  else
    # Insert before </ossec_config>
    sed -i "s|</ossec_config>|${LOCALFILE_BLOCK}\n</ossec_config>|" "$OSSEC_CONF"
    success "Added localfile to: $OSSEC_CONF"
    # Restart Wazuh agent
    if command -v systemctl &>/dev/null && systemctl is-active --quiet wazuh-agent; then
      systemctl restart wazuh-agent
      success "Wazuh agent restarted."
    fi
  fi
else
  warn "Wazuh ossec.conf not found at $OSSEC_CONF"
  warn "Add this block manually to ossec.conf:"
  echo "$LOCALFILE_BLOCK"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo -e "  ${BOLD}Log file:${NC}      $LOG_FILE"
echo -e "  ${BOLD}Config:${NC}        $CONFIG_FILE"
echo -e "  ${BOLD}Service:${NC}       systemctl status $SERVICE_NAME"
echo -e "  ${BOLD}Live tail:${NC}     tail -f $LOG_FILE | python3 -m json.tool"
echo -e "  ${BOLD}Uninstall:${NC}     sudo bash linux-installer.sh --uninstall"
echo ""
echo -e "${CYAN}Design: collect raw locally → detect locally → send only REDACTED to Wazuh${NC}"
echo ""
