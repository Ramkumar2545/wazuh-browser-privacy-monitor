#!/usr/bin/env bash
# =============================================================================
#  Wazuh Browser Privacy Monitor Phase 3 - Linux Standalone Installer
#  Author  : Ram Kumar G (IT Fortress)
#  Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)
#
#  Installs:
#    Collector   → /opt/browser-privacy-monitor/
#    Log + State → /root/.browser-privacy-monitor/
#    Service     → /etc/systemd/system/browser-privacy-monitor.service
#    Wazuh conf  → /var/ossec/etc/ossec.conf (log_format=json)
#
#  ONE-LINE INSTALL:
#    sudo bash -c "$(curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.sh)"
#
#  OR from cloned repo:
#    sudo bash installers/linux-installer.sh
#    sudo bash installers/linux-installer.sh --interval 300
#    sudo bash installers/linux-installer.sh --uninstall
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

INSTALL_OPT="/opt/browser-privacy-monitor"
DATA_DIR="/root/.browser-privacy-monitor"
LOG_FILE="$DATA_DIR/browser_privacy.log"
CONFIG_FILE="$DATA_DIR/.browser_privacy_config.json"
SERVICE_NAME="browser-privacy-monitor"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_NAME="browser-privacy-monitor.py"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
REPO_RAW="https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main"

# ── Parse CLI args ─────────────────────────────────────────────────────────────
# Supports:
#   --interval <seconds>      e.g. --interval 300
#   --interval <Nm|Nh|Nd>     e.g. --interval 30m, 2h, 1d
#   --interval <1-10>         menu shortcut, same numbering as the prompt
#   -y | --yes | --non-interactive   accept defaults, never prompt
#   --uninstall               remove everything
# Env vars: BPM_INTERVAL=30m   BPM_NONINTERACTIVE=1
UNINSTALL=false
CLI_INTERVAL="${BPM_INTERVAL:-}"
NONINTERACTIVE="${BPM_NONINTERACTIVE:-0}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interval=*) CLI_INTERVAL="${1#*=}"; shift ;;
        --interval)   CLI_INTERVAL="$2"; shift 2 ;;
        -y|--yes|--non-interactive) NONINTERACTIVE=1; shift ;;
        --uninstall)  UNINSTALL=true; shift ;;
        -h|--help)
            echo "Usage: linux-installer.sh [--interval <value>] [-y|--non-interactive] [--uninstall]"
            echo "  --interval 1..10   menu number (1=1m, 2=5m, ..., 5=30m, ..., 10=24h)"
            echo "  --interval 300     raw seconds"
            echo "  --interval 30m     short form (m=minutes, h=hours, d=days)"
            echo "  -y                 non-interactive (default 30m)"
            echo "Env vars: BPM_INTERVAL, BPM_NONINTERACTIVE"
            exit 0
            ;;
        *) shift ;;
    esac
done

# ── INTERVAL PARSER ───────────────────────────────────────────────────────────
parse_interval() {
    local v="$1"
    [ -z "$v" ] && v="5"
    case "$v" in
        1)  SECS=60;    LABEL="1m"  ;;
        2)  SECS=300;   LABEL="5m"  ;;
        3)  SECS=600;   LABEL="10m" ;;
        4)  SECS=1200;  LABEL="20m" ;;
        5)  SECS=1800;  LABEL="30m" ;;
        6)  SECS=3600;  LABEL="60m" ;;
        7)  SECS=7200;  LABEL="2h"  ;;
        8)  SECS=21600; LABEL="6h"  ;;
        9)  SECS=43200; LABEL="12h" ;;
        10) SECS=86400; LABEL="24h" ;;
        *[0-9]m) SECS=$(( ${v%m} * 60 ));    LABEL="$v" ;;
        *[0-9]h) SECS=$(( ${v%h} * 3600 ));  LABEL="$v" ;;
        *[0-9]d) SECS=$(( ${v%d} * 86400 )); LABEL="$v" ;;
        *[!0-9]*) SECS=1800; LABEL="30m" ;;
        *)        SECS="$v"; LABEL="${v}s" ;;
    esac
    if [ "$SECS" -lt 60 ] 2>/dev/null;    then SECS=60;    LABEL="1m";  fi
    if [ "$SECS" -gt 86400 ] 2>/dev/null; then SECS=86400; LABEL="24h"; fi
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
if $UNINSTALL; then
    echo -e "${YELLOW}[UNINSTALL] Removing $SERVICE_NAME...${NC}"
    systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f  "$SERVICE_FILE"
    rm -rf "$INSTALL_OPT"
    systemctl daemon-reload
    echo -e "${GREEN}[OK] Uninstalled. Data at $DATA_DIR kept for log retention.${NC}"
    exit 0
fi

[[ $EUID -ne 0 ]] && { echo -e "${RED}[-] Run as root: sudo bash linux-installer.sh${NC}"; exit 1; }

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Privacy Monitor Phase 3 - Linux Installer         ║${NC}"
echo -e "${BLUE}║  Version 1.0.0 | IT Fortress | Privacy-Safe Telemetry           ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "${CYAN}  Design: Raw URLs stay on endpoint — Wazuh only receives redacted JSON${NC}"
echo -e ""

# ── STEP 1: Python check ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON=""
for py in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then PYTHON=$(command -v "$py"); break; fi
done
[[ -z "$PYTHON" ]] && { echo -e "${RED}[-] Python 3 not found. Install with: apt install python3${NC}"; exit 1; }
echo -e "${GREEN}    [+] $($PYTHON --version 2>&1) → $PYTHON${NC}"

# ── STEP 2: Interval selection ────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[2] Select scan interval (how often to check browser history):${NC}"
echo -e "     1)  ${CYAN}1  minute${NC}   (high I/O — testing only)"
echo -e "     2)  5  minutes"
echo -e "     3)  10 minutes"
echo -e "     4)  20 minutes"
echo -e "     5)  ${CYAN}30 minutes${NC}  (recommended)"
echo -e "     6)  60 minutes / 1 hour"
echo -e "     7)  2  hours"
echo -e "     8)  6  hours"
echo -e "     9)  12 hours"
echo -e "    10)  24 hours   (once per day)"
echo -e ""

# Priority: CLI flag / env → non-interactive mode → TTY prompt → /dev/tty reopen → default
if [[ -n "$CLI_INTERVAL" ]]; then
    parse_interval "$CLI_INTERVAL"
    echo -e "${GREEN}    [+] Using interval from flag/env: $LABEL ($SECS seconds)${NC}"
elif [[ "$NONINTERACTIVE" = "1" ]]; then
    parse_interval "5"
    echo -e "    ${YELLOW}(Non-interactive mode: default $LABEL)${NC}"
else
    # /dev/tty reopen trick so 'curl ... | sudo bash' can still prompt
    if [ -t 0 ]; then
        PROMPT_FD=0
    elif [ -r /dev/tty ] && [ -w /dev/tty ]; then
        exec </dev/tty
        PROMPT_FD=0
    else
        PROMPT_FD=""
    fi

    if [ -n "$PROMPT_FD" ]; then
        read -rp "    Enter choice [1-10] (default: 5 = 30 min): " CHOICE
        [ -z "$CHOICE" ] && CHOICE="5"
        parse_interval "$CHOICE"
    else
        parse_interval "5"
        echo -e "    ${YELLOW}(No TTY detected: defaulting to $LABEL — pass --interval or -y to override)${NC}"
    fi
fi
echo -e "${GREEN}    [+] Selected: $LABEL ($SECS seconds)${NC}"

# ── STEP 3: Create dirs & download ───────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[3] Installing to $INSTALL_OPT...${NC}"
mkdir -p "$INSTALL_OPT" "$DATA_DIR"
SCRIPT_DST="$INSTALL_OPT/$SCRIPT_NAME"

SCRIPT_LOCAL="$(dirname "$0")/../collector/$SCRIPT_NAME"
if [[ -f "$SCRIPT_LOCAL" ]]; then
    cp "$SCRIPT_LOCAL" "$SCRIPT_DST"
    echo -e "${GREEN}    [+] Installed from local copy${NC}"
elif command -v curl &>/dev/null; then
    curl -sSL "$REPO_RAW/collector/$SCRIPT_NAME" -o "$SCRIPT_DST"
    echo -e "${GREEN}    [+] Downloaded from GitHub${NC}"
elif command -v wget &>/dev/null; then
    wget -qO "$SCRIPT_DST" "$REPO_RAW/collector/$SCRIPT_NAME"
    echo -e "${GREEN}    [+] Downloaded from GitHub (wget)${NC}"
else
    echo -e "${RED}[-] Cannot install: curl/wget not available.${NC}"; exit 1
fi

chmod 700 "$SCRIPT_DST"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
echo -e "${GREEN}    [+] Collector: $SCRIPT_DST${NC}"
echo -e "${GREEN}    [+] Log file : $LOG_FILE  [JSON — NO raw URLs]${NC}"

# ── STEP 4: Write config ──────────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[4] Writing interval config...${NC}"
cat > "$CONFIG_FILE" <<CONFIG
{
  "scan_interval_seconds": $SECS,
  "scan_interval_label": "$LABEL",
  "version": "1.0.0"
}
CONFIG
chmod 600 "$CONFIG_FILE"
echo -e "${GREEN}    [+] Config: $CONFIG_FILE  [$LABEL = ${SECS}s]${NC}"

# ── STEP 5: systemd service ───────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[5] Creating systemd service...${NC}"
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Wazuh Browser Privacy Monitor Phase 3 — Privacy-Safe Telemetry
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
    echo -e "${GREEN}    [+] Service running: $SERVICE_NAME${NC}"
else
    echo -e "${YELLOW}    [!] Check: journalctl -u $SERVICE_NAME -n 20${NC}"
fi

# ── STEP 6: Wazuh ossec.conf ──────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[6] Configuring Wazuh ossec.conf (log_format=json)...${NC}"
MARKER="<!-- BROWSER_PRIVACY_MONITOR_P3 -->"
if [[ -f "$OSSEC_CONF" ]]; then
    if grep -q "$MARKER" "$OSSEC_CONF"; then
        echo -e "${GREEN}    [=] Already configured — skipping${NC}"
    else
        sed -i "s|</ossec_config>|\n  ${MARKER}\n  <localfile>\n    <log_format>json</log_format>\n    <location>${LOG_FILE}</location>\n    <label key=\"integration\">browser-privacy-monitor</label>\n  </localfile>\n</ossec_config>|" "$OSSEC_CONF"
        systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart 2>/dev/null || true
        echo -e "${GREEN}    [+] localfile added and Wazuh agent restarted${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $OSSEC_CONF${NC}"
    echo    "    Add manually:"
    echo    "      <localfile>"
    echo    "        <log_format>json</log_format>"
    echo    "        <location>$LOG_FILE</location>"
    echo    "        <label key=\"integration\">browser-privacy-monitor</label>"
    echo    "      </localfile>"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  [SUCCESS] Phase 3 Installation Complete!                        ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo    "  Interval  : $LABEL ($SECS seconds)"
echo    "  Log file  : $LOG_FILE  [JSON — NO raw URLs, NO tokens]"
echo -e "  Watch log : ${CYAN}tail -f $LOG_FILE | python3 -m json.tool${NC}"
echo -e "  Service   : ${CYAN}systemctl status $SERVICE_NAME${NC}"
echo -e "  Journal   : ${CYAN}journalctl -u $SERVICE_NAME -f${NC}"
echo -e "  Uninstall : ${CYAN}sudo bash linux-installer.sh --uninstall${NC}"
echo -e ""
echo -e "${CYAN}  Wazuh Manager next steps:${NC}"
echo    "    1. Copy wazuh/rules/0320-browser_privacy_rules.xml     → /var/ossec/etc/rules/"
echo    "    2. Copy wazuh/decoders/0320-browser_privacy_decoder.xml → /var/ossec/etc/decoders/"
echo    "    3. /var/ossec/bin/wazuh-logtest -V && systemctl restart wazuh-manager"
echo -e ""
echo -e "${CYAN}  Design: collect raw locally → detect locally → send ONLY redacted JSON to Wazuh${NC}"
echo -e ""
