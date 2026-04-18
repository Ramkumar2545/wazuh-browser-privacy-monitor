#!/bin/bash
# =============================================================================
#  Wazuh Browser Privacy Monitor Phase 3 - Linux / macOS One-Line Installer
#  Author  : Ram Kumar G (IT Fortress)
#  Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)
#
#  Supports:
#    Linux : Ubuntu 20.04+, Debian 11+, AlmaLinux 8+, RHEL 8+, CentOS 8+
#    macOS : 12 Monterey, 13 Ventura, 14 Sonoma, 15 Sequoia
#
#  ONE-LINE INSTALL:
#    Linux:
#      curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.sh | sudo bash
#
#    macOS:
#      curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.sh | bash
#
#  DESIGN: collect raw locally → detect locally → send only REDACTED to Wazuh
#  Raw URLs, tokens, session IDs, API keys are NEVER written to the Wazuh log.
# =============================================================================

set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPO_RAW="https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main"
OS_TYPE="$(uname -s)"

# ── CLI ARGUMENT PARSING ──────────────────────────────────────────────────────
# Supports:
#   --interval <seconds>      e.g. --interval 300
#   --interval <Nm|Nh|Nd>     e.g. --interval 30m, --interval 2h, --interval 1d
#   --interval <1-10>         menu shortcut, same numbering as the prompt
#   -y | --yes | --non-interactive   accept defaults, never prompt
# Env-var equivalent: BPM_INTERVAL=30m  or  BPM_NONINTERACTIVE=1
CLI_INTERVAL="${BPM_INTERVAL:-}"
NONINTERACTIVE="${BPM_NONINTERACTIVE:-0}"
while [ $# -gt 0 ]; do
    case "$1" in
        --interval=*) CLI_INTERVAL="${1#*=}"; shift ;;
        --interval)   CLI_INTERVAL="$2"; shift 2 ;;
        -y|--yes|--non-interactive) NONINTERACTIVE=1; shift ;;
        -h|--help)
            echo "Usage: install.sh [--interval <value>] [-y|--non-interactive]"
            echo "  --interval 1..10     menu number (1=1m, 2=5m, ..., 5=30m, ..., 10=24h)"
            echo "  --interval 300       raw seconds"
            echo "  --interval 30m       short form (m=minutes, h=hours, d=days)"
            echo "  -y, --non-interactive  skip prompts and use default (30m)"
            echo "Env vars: BPM_INTERVAL, BPM_NONINTERACTIVE"
            exit 0
            ;;
        *) shift ;;  # ignore unknowns silently so 'curl | bash -s --' works
    esac
done

# ── INTERVAL PARSER ───────────────────────────────────────────────────────────
# Accepts:  menu number 1-10   |   raw seconds   |   30m / 2h / 1d shorthand
# Returns via globals: SECS, LABEL
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
        *[!0-9]*) SECS=1800; LABEL="30m" ;;     # anything else with non-digits = default
        *)        SECS="$v"; LABEL="${v}s" ;;    # pure digits = raw seconds
    esac
    # Clamp to sane range [60, 86400]
    if [ "$SECS" -lt 60 ] 2>/dev/null;    then SECS=60;    LABEL="1m";  fi
    if [ "$SECS" -gt 86400 ] 2>/dev/null; then SECS=86400; LABEL="24h"; fi
}

# ── Paths (OS-aware) ──────────────────────────────────────────────────────────
if [ "$OS_TYPE" = "Darwin" ]; then
    INSTALL_DIR="$HOME/.browser-privacy-monitor"
    WAZUH_CONF="/Library/Ossec/etc/ossec.conf"
else
    INSTALL_DIR="/root/.browser-privacy-monitor"
    WAZUH_CONF="/var/ossec/etc/ossec.conf"
fi

DEST_SCRIPT="$INSTALL_DIR/browser-privacy-monitor.py"
CONFIG_FILE="$INSTALL_DIR/.browser_privacy_config.json"
LOG_FILE="$INSTALL_DIR/browser_privacy.log"
SERVICE_NAME="browser-privacy-monitor"

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Privacy Monitor Phase 3                           ║${NC}"
echo -e "${BLUE}║  Linux / macOS Installer  v1.0.0                                 ║${NC}"
echo -e "${BLUE}║  IT Fortress | Privacy-Safe Telemetry | Redacted Before Wazuh    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "${CYAN}  Design: Raw URLs stay on endpoint — Wazuh only receives redacted JSON${NC}"
echo -e ""

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then PYTHON_BIN=$(command -v "$py"); break; fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    if   command -v apt-get &>/dev/null; then echo "    Run: sudo apt install -y python3"
    elif command -v dnf     &>/dev/null; then echo "    Run: sudo dnf install -y python3"
    elif command -v yum     &>/dev/null; then echo "    Run: sudo yum install -y python3"
    elif [ "$OS_TYPE" = "Darwin" ];      then echo "    Run: brew install python3"
    fi
    exit 1
fi
echo -e "${GREEN}    [+] $($PYTHON_BIN --version 2>&1) → $PYTHON_BIN${NC}"

# ── STEP 2: INTERVAL SELECTION ────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[2] Select scan interval (how often to check browser history):${NC}"
echo -e "     1)  ${CYAN}1  minute${NC}   (high I/O — use for testing only)"
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

# Decide how to get the interval, in priority order:
#   1. --interval / BPM_INTERVAL
#   2. Interactive prompt (TTY on stdin OR /dev/tty available when piped)
#   3. Default 30m (non-interactive fallback)
if [ -n "$CLI_INTERVAL" ]; then
    parse_interval "$CLI_INTERVAL"
    echo -e "${GREEN}    [+] Using interval from flag/env: $LABEL ($SECS seconds)${NC}"
elif [ "$NONINTERACTIVE" = "1" ]; then
    parse_interval "5"
    echo -e "    ${YELLOW}(Non-interactive mode: default $LABEL)${NC}"
else
    # Works for direct runs AND 'curl ... | sudo bash':
    #   - If stdin is already a TTY, read from it.
    #   - Else try to reopen stdin from /dev/tty so the pipe still prompts.
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
        echo -e "    ${YELLOW}(No TTY available — defaulting to $LABEL. Re-run with --interval <value> or set BPM_INTERVAL.)${NC}"
    fi
fi

echo -e "${GREEN}    [+] Selected: $LABEL ($SECS seconds)${NC}"

# ── STEP 3: CREATE INSTALL DIR & DOWNLOAD ────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[3] Installing to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"

# Download collector
if command -v curl &>/dev/null; then
    curl -sSL "$REPO_RAW/collector/browser-privacy-monitor.py" -o "$DEST_SCRIPT"
elif command -v wget &>/dev/null; then
    wget -qO "$DEST_SCRIPT" "$REPO_RAW/collector/browser-privacy-monitor.py"
else
    echo -e "${RED}[-] Neither curl nor wget found. Cannot download collector.${NC}"; exit 1
fi

chmod 700 "$DEST_SCRIPT"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
echo -e "${GREEN}    [+] Collector : $DEST_SCRIPT${NC}"
echo -e "${GREEN}    [+] Log file  : $LOG_FILE${NC}"

# ── STEP 4: WRITE CONFIG ──────────────────────────────────────────────────────
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

# ── STEP 5: REGISTER PERSISTENCE ─────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[5] Registering persistence...${NC}"

if [ "$OS_TYPE" = "Darwin" ]; then
    # ── macOS: LaunchAgent ────────────────────────────────────────────────────
    PLIST_DIR="$HOME/Library/LaunchAgents"
    LABEL_ID="com.ramkumar.browser-privacy-monitor"
    PLIST_FILE="$PLIST_DIR/$LABEL_ID.plist"
    mkdir -p "$PLIST_DIR"

    cat > "$PLIST_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL_ID</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$DEST_SCRIPT</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>$SECS</integer>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/error.log</string>
</dict>
</plist>
PLIST

    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load   "$PLIST_FILE"
    sleep 2
    if launchctl list | grep -q "$LABEL_ID"; then
        echo -e "${GREEN}    [+] LaunchAgent running: $LABEL_ID (interval: $LABEL)${NC}"
    else
        echo -e "${YELLOW}    [!] LaunchAgent may not have started.${NC}"
        echo -e "        Grant Full Disk Access to Python in:"
        echo -e "        System Settings → Privacy & Security → Full Disk Access → Add: $PYTHON_BIN"
        echo -e "        Then: launchctl unload $PLIST_FILE && launchctl load $PLIST_FILE"
    fi

else
    # ── Linux: systemd (root or user) ─────────────────────────────────────────
    if [ "$(id -u)" = "0" ]; then
        # root — system-wide service
        SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
        cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Wazuh Browser Privacy Monitor Phase 3
Documentation=https://github.com/Ramkumar2545/wazuh-browser-privacy-monitor
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON_BIN $DEST_SCRIPT
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10
StandardOutput=null
StandardError=journal
SyslogIdentifier=browser-privacy-monitor
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME"
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}    [+] systemd system service running: $SERVICE_NAME${NC}"
        else
            echo -e "${YELLOW}    [!] Check: journalctl -u $SERVICE_NAME -n 20${NC}"
        fi
    else
        # user — systemd user service
        SERVICE_DIR="$HOME/.config/systemd/user"
        SERVICE_FILE="$SERVICE_DIR/${SERVICE_NAME}.service"
        mkdir -p "$SERVICE_DIR"
        cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Wazuh Browser Privacy Monitor Phase 3
Documentation=https://github.com/Ramkumar2545/wazuh-browser-privacy-monitor
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON_BIN $DEST_SCRIPT
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10
StandardOutput=null
StandardError=journal

[Install]
WantedBy=default.target
SERVICE
        systemctl --user daemon-reload
        systemctl --user enable "$SERVICE_NAME"
        systemctl --user restart "$SERVICE_NAME"
        sleep 2
        if systemctl --user is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}    [+] systemd user service running: $SERVICE_NAME${NC}"
        else
            echo -e "${YELLOW}    [!] Check: journalctl --user -u $SERVICE_NAME -n 20${NC}"
        fi
        if command -v loginctl &>/dev/null; then
            loginctl enable-linger "$USER" 2>/dev/null || true
            echo -e "${GREEN}    [+] loginctl linger enabled for $USER${NC}"
        fi
    fi
fi

# ── STEP 6: WAZUH OSSEC.CONF ──────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[6] Configuring Wazuh ossec.conf...${NC}"
MARKER="<!-- BROWSER_PRIVACY_MONITOR_P3 -->"

if [ -f "$WAZUH_CONF" ]; then
    if grep -q "$MARKER" "$WAZUH_CONF" 2>/dev/null; then
        echo -e "${GREEN}    [=] localfile block already present — skipping${NC}"
    else
        LOCALFILE_BLOCK="\n  <!-- BROWSER_PRIVACY_MONITOR_P3 -->\n  <localfile>\n    <log_format>json</log_format>\n    <location>$LOG_FILE</location>\n    <label key=\"integration\">browser-privacy-monitor</label>\n  </localfile>"

        if [ "$OS_TYPE" = "Darwin" ]; then
            sed -i '' "s|</ossec_config>|${LOCALFILE_BLOCK}\n</ossec_config>|" "$WAZUH_CONF"
            /Library/Ossec/bin/wazuh-control restart 2>/dev/null || true
        else
            sed -i "s|</ossec_config>|${LOCALFILE_BLOCK}\n</ossec_config>|" "$WAZUH_CONF"
            systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart 2>/dev/null || true
        fi
        echo -e "${GREEN}    [+] localfile block added to: $WAZUH_CONF${NC}"
        echo -e "${GREEN}    [+] Wazuh agent restarted${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $WAZUH_CONF${NC}"
    echo -e "    Add manually inside <ossec_config>:"
    echo -e "      <!-- BROWSER_PRIVACY_MONITOR_P3 -->"
    echo -e "      <localfile>"
    echo -e "        <log_format>json</log_format>"
    echo -e "        <location>$LOG_FILE</location>"
    echo -e "        <label key=\"integration\">browser-privacy-monitor</label>"
    echo -e "      </localfile>"
fi

# ── DONE ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  [SUCCESS] Phase 3 Installation Complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo    "  Interval  : $LABEL ($SECS seconds)"
echo    "  Log file  : $LOG_FILE  [JSON — NO raw URLs, NO tokens]"
echo -e "  Watch log : ${CYAN}tail -f $LOG_FILE | python3 -m json.tool${NC}"

if [ "$OS_TYPE" = "Darwin" ]; then
    echo -e "  Service   : ${CYAN}launchctl list | grep browser-privacy-monitor${NC}"
    echo -e ""
    echo -e "${YELLOW}  ⚠ IMPORTANT (macOS): Grant Full Disk Access to Python${NC}"
    echo    "     System Settings → Privacy & Security → Full Disk Access → Add: $PYTHON_BIN"
elif [ "$(id -u)" = "0" ]; then
    echo -e "  Service   : ${CYAN}systemctl status browser-privacy-monitor${NC}"
    echo -e "  Logs      : ${CYAN}journalctl -u browser-privacy-monitor -f${NC}"
else
    echo -e "  Service   : ${CYAN}systemctl --user status browser-privacy-monitor${NC}"
    echo -e "  Logs      : ${CYAN}journalctl --user -u browser-privacy-monitor -f${NC}"
fi

echo -e ""
echo -e "${CYAN}  Wazuh Manager next steps:${NC}"
echo    "    1. Copy  wazuh/rules/0320-browser_privacy_rules.xml     → /var/ossec/etc/rules/"
echo    "    2. Copy  wazuh/decoders/0320-browser_privacy_decoder.xml → /var/ossec/etc/decoders/"
echo    "    3. Run   /var/ossec/bin/wazuh-logtest -V && systemctl restart wazuh-manager"
echo -e ""
echo -e "${CYAN}  Design: collect raw locally → detect locally → send ONLY redacted JSON to Wazuh${NC}"
echo -e ""
