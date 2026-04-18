#!/bin/bash
# =============================================================================
#  Wazuh Browser Privacy Monitor Phase 3 - macOS Standalone Installer
#  Author  : Ram Kumar G (IT Fortress)
#  Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)
#  Supports: macOS 12 Monterey, 13 Ventura, 14 Sonoma, 15 Sequoia
#
#  ONE-LINE (from cloned repo):
#    bash installers/macos-installer.sh
#    bash installers/macos-installer.sh --interval 300
#    bash installers/macos-installer.sh --interval 30m
#    bash installers/macos-installer.sh -y       # non-interactive (default 30m)
#
#  OR via curl:
#    curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.sh | bash
#
#  Env vars: BPM_INTERVAL=30m   BPM_NONINTERACTIVE=1
# =============================================================================

set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# ── CLI ARG PARSING ───────────────────────────────────────────────────────────
CLI_INTERVAL="${BPM_INTERVAL:-}"
NONINTERACTIVE="${BPM_NONINTERACTIVE:-0}"
while [ $# -gt 0 ]; do
    case "$1" in
        --interval=*) CLI_INTERVAL="${1#*=}"; shift ;;
        --interval)   CLI_INTERVAL="$2"; shift 2 ;;
        -y|--yes|--non-interactive) NONINTERACTIVE=1; shift ;;
        -h|--help)
            echo "Usage: macos-installer.sh [--interval <value>] [-y|--non-interactive]"
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

REPO_ROOT="$(dirname "$(dirname "$(realpath "$0")")")"
SOURCE_SCRIPT="$REPO_ROOT/collector/browser-privacy-monitor.py"
INSTALL_DIR="$HOME/.browser-privacy-monitor"
DEST_SCRIPT="$INSTALL_DIR/browser-privacy-monitor.py"
CONFIG_FILE="$INSTALL_DIR/.browser_privacy_config.json"
LOG_FILE="$INSTALL_DIR/browser_privacy.log"
PLIST_DIR="$HOME/Library/LaunchAgents"
LABEL_ID="com.ramkumar.browser-privacy-monitor"
PLIST_FILE="$PLIST_DIR/$LABEL_ID.plist"
WAZUH_CONF="/Library/Ossec/etc/ossec.conf"

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Privacy Monitor Phase 3 - macOS Installer         ║${NC}"
echo -e "${BLUE}║  IT Fortress | Privacy-Safe Telemetry                            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "${CYAN}  Design: Raw URLs stay on endpoint — Wazuh only receives redacted JSON${NC}"
echo -e ""
echo -e "  macOS: $(sw_vers -productVersion)"

# ── STEP 1: Python check ──────────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3 $(which python3 2>/dev/null); do
    if [ -x "$py" ]; then PYTHON_BIN="$py"; break; fi
done
if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    echo "    Install via Homebrew: brew install python3"
    echo "    Or download: https://python.org"
    exit 1
fi
echo -e "${GREEN}    [+] $($PYTHON_BIN --version 2>&1) → $PYTHON_BIN${NC}"

# ── STEP 2: Interval selection ────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[2] Select scan interval:${NC}"
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
if [ -n "$CLI_INTERVAL" ]; then
    parse_interval "$CLI_INTERVAL"
    echo -e "${GREEN}    [+] Using interval from flag/env: $LABEL ($SECS seconds)${NC}"
elif [ "$NONINTERACTIVE" = "1" ]; then
    parse_interval "5"
    echo -e "    ${YELLOW}(Non-interactive mode: default $LABEL)${NC}"
else
    # /dev/tty reopen so 'curl ... | bash' still prompts
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

# ── STEP 3: Install files ─────────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[3] Installing to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"

if [ -f "$SOURCE_SCRIPT" ]; then
    cp "$SOURCE_SCRIPT" "$DEST_SCRIPT"
    echo -e "${GREEN}    [+] Installed from local copy${NC}"
elif command -v curl &>/dev/null; then
    curl -sSL "https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/collector/browser-privacy-monitor.py" -o "$DEST_SCRIPT"
    echo -e "${GREEN}    [+] Downloaded from GitHub${NC}"
else
    echo -e "${RED}[-] Cannot find collector script. Clone the repo first.${NC}"; exit 1
fi

chmod 700 "$DEST_SCRIPT"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
echo -e "${GREEN}    [+] Log file: $LOG_FILE${NC}"

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

# ── STEP 5: LaunchAgent ───────────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[5] Creating LaunchAgent...${NC}"
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
    echo -e "${YELLOW}    [!] LaunchAgent may not have started — Full Disk Access required.${NC}"
    echo -e "        System Settings → Privacy & Security → Full Disk Access → Add: $PYTHON_BIN"
fi

# ── STEP 6: Wazuh ossec.conf ──────────────────────────────────────────────────
echo -e ""
echo -e "${YELLOW}[6] Configuring Wazuh ossec.conf...${NC}"
MARKER="<!-- BROWSER_PRIVACY_MONITOR_P3 -->"
if [ -f "$WAZUH_CONF" ]; then
    if grep -q "$MARKER" "$WAZUH_CONF" 2>/dev/null; then
        echo -e "${GREEN}    [=] localfile block already present — skipping${NC}"
    else
        sed -i '' "s|</ossec_config>|\n  <!-- BROWSER_PRIVACY_MONITOR_P3 -->\n  <localfile>\n    <log_format>json</log_format>\n    <location>$LOG_FILE</location>\n    <label key=\"integration\">browser-privacy-monitor</label>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        /Library/Ossec/bin/wazuh-control restart 2>/dev/null || true
        echo -e "${GREEN}    [+] localfile added and Wazuh agent restarted${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $WAZUH_CONF${NC}"
    echo    "    Add manually: <localfile><log_format>json</log_format><location>$LOG_FILE</location></localfile>"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}[SUCCESS] Phase 3 Installation Complete!${NC}"
echo -e ""
echo    "  Interval  : $LABEL ($SECS seconds)"
echo    "  Log file  : $LOG_FILE"
echo -e "  Watch log : ${CYAN}tail -f $LOG_FILE | python3 -m json.tool${NC}"
echo -e "  Service   : ${CYAN}launchctl list | grep browser-privacy-monitor${NC}"
echo -e ""
echo -e "${YELLOW}  ⚠ IMPORTANT: Grant Full Disk Access to Python${NC}"
echo    "     System Settings → Privacy & Security → Full Disk Access → Add: $PYTHON_BIN"
echo -e ""
