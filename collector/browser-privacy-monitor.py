#!/usr/bin/env python3
"""
Wazuh Browser Privacy Monitor
Author  : Ram Kumar G (IT Fortress)
Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)
Platform: Windows | Linux | macOS
Browsers: Chrome, Edge, Brave, Firefox, Opera, OperaGX, Vivaldi,
          Waterfox, Tor, Chromium, Safari (macOS)
          All install types: standard, snap, flatpak

DESIGN PRINCIPLE (Phase 3):
  "Collect raw locally, detect locally, store centrally only in redacted form."

  This script extends the Phase 2 browser history collector with a full
  endpoint-side privacy redaction engine. Raw sensitive values (tokens,
  passwords, session IDs, API keys, email addresses, reset links) are NEVER
  written to the log file that Wazuh ingests.

  What gets sent to Wazuh:
    - domain          : hostname only (no path/query)
    - browser         : browser name
    - endpoint        : hostname
    - user            : username
    - browser_profile : profile directory name
    - timestamp       : ISO 8601 visit time
    - risk_category   : e.g. credential_page, auth_token, file_download, etc.
    - sensitive_detected: true/false
    - sensitive_type  : token, credential, email, internal_doc, auth_code,
                        api_key, session_id, password_reset, personal_query
    - url_redacted    : masked URL  e.g. https://portal.com/reset?token=***REDACTED***
    - url_hash        : SHA-256 of full URL for correlation (never cleartext)
    - title_redacted  : masked page title
    - title_hash      : SHA-256 of full title
    - risk_score      : 0-10 integer

  Protection Layers:
    1. Endpoint-side redaction  (this script, before log write)
    2. Indexer-side safeguards  (wazuh/pipelines/ ingest config)
    3. Dashboard access control (field exclusion + role-based access)

CHANGELOG:
  1.0.0 - Initial Phase 3 release
          Full privacy redaction engine
          JSON-format log output (one event per line)
          Configurable scan interval from .browser_privacy_config.json
          All Phase 2 browser/profile/platform support inherited
"""

import os
import sys
import re
import time
import sqlite3
import shutil
import platform
import json
import hashlib
import logging
import socket
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
VERSION            = "1.0.0"
CHROME_EPOCH_DIFF  = 11644473600
MAC_EPOCH_DIFF     = 978307200
LOG_FILE_NAME      = "browser_privacy.log"
CONFIG_FILE_NAME   = ".browser_privacy_config.json"
DEFAULT_INTERVAL   = 300   # 5 minutes default for Phase 3

# ──────────────────────────────────────────────────────────────────────────────
# SENSITIVE PATTERN CATALOGUE
# All patterns match against: query strings, paths, or full URLs
# ──────────────────────────────────────────────────────────────────────────────

# Parameter names that always contain sensitive values
SENSITIVE_PARAMS = {
    "token", "access_token", "refresh_token", "id_token", "bearer",
    "api_key", "apikey", "api-key", "key",
    "secret", "client_secret",
    "password", "passwd", "pwd",
    "code", "auth_code", "authorization_code",
    "session", "session_id", "sessionid", "sid", "sess",
    "ticket", "nonce", "state",
    "reset", "reset_token", "reset_key", "recovery_token",
    "magic", "magic_link", "logintoken",
    "oauth_token", "oauth_verifier",
    "jwt", "saml_response",
    "csrf", "csrftoken", "_token",
    "x-auth-token", "x-api-key",
    "ssid", "cookie",
}

# URL path fragments that indicate sensitive pages
SENSITIVE_PATH_PATTERNS = [
    (re.compile(r'/(reset|forgot)[_-]?password', re.I),       "password_reset"),
    (re.compile(r'/magic[_-]?link', re.I),                    "magic_link"),
    (re.compile(r'/auth/(callback|redirect|response)', re.I), "auth_code"),
    (re.compile(r'/oauth2?/(callback|token|authorize)', re.I),"auth_code"),
    (re.compile(r'/saml/(response|callback|acs)', re.I),      "auth_code"),
    (re.compile(r'/sso/(login|callback|return)', re.I),       "auth_code"),
    (re.compile(r'/verify[_-]?email', re.I),                  "auth_code"),
    (re.compile(r'/activate[_-]?account', re.I),              "auth_code"),
    (re.compile(r'/unsubscribe', re.I),                       "personal_query"),
    (re.compile(r'/export', re.I),                            "internal_doc"),
    (re.compile(r'/download', re.I),                          "internal_doc"),
    (re.compile(r'/(admin|manage|console|dashboard)', re.I),  "internal_doc"),
    (re.compile(r'/api/(v\d+/)?', re.I),                      "api_key"),
    (re.compile(r'/graphql', re.I),                           "api_key"),
    (re.compile(r'\.(exe|msi|ps1|bat|cmd|hta|vbs|jar|iso|img|dll|scr|pif)$', re.I), "file_download"),
]

# High-entropy token pattern (catches raw tokens/keys not in a named param)
HIGH_ENTROPY_PATTERN = re.compile(
    r'(?<![a-zA-Z0-9])'          # not preceded by alnum
    r'[A-Za-z0-9+/._~-]{32,}'   # 32+ char token-like string
    r'(?![a-zA-Z0-9])',
    re.ASCII
)

# Email in query string
EMAIL_IN_QUERY = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Credential/auth page detection by URL pattern
CREDENTIAL_PAGE_PATTERNS = re.compile(
    r'/(login|signin|sign[_-]in|logon|log[_-]in'
    r'|verify|mfa|otp|2fa|two[_-]factor'
    r'|reset[_-]password|password[_-]reset'
    r'|account[_-]recovery|recover'
    r'|forgot|change[_-]password)',
    re.I
)

ANONYMIZER_PATTERNS = re.compile(
    r'(\.onion$|torproject\.org|protonvpn|nordvpn|expressvpn'
    r'|surfshark|hidemy\.name|anonymox|kproxy|hidemyass'
    r'|anonymouse\.org|whoer\.net)',
    re.I
)

CLOUD_STORAGE_PATTERNS = re.compile(
    r'(drive\.google\.com|dropbox\.com|onedrive\.live\.com'
    r'|box\.com|mega\.nz|wetransfer\.com|mediafire\.com'
    r'|4shared\.com|zippyshare\.com|anonfiles\.com)',
    re.I
)

# Risk score lookup by sensitive_type
RISK_SCORES = {
    "auth_token":       10,
    "session_id":       10,
    "password_reset":   10,
    "magic_link":       10,
    "auth_code":         9,
    "api_key":           9,
    "credential":        8,
    "token":             8,
    "email":             6,
    "internal_doc":      6,
    "personal_query":    5,
    "file_download":     7,
    "anonymizer":        7,
    "cloud_storage":     5,
    "credential_page":   8,
    "none":              3,
}

# ──────────────────────────────────────────────────────────────────────────────
# TIME HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def chrome_time(ts):
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromtimestamp((ts / 1_000_000) - CHROME_EPOCH_DIFF, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%dT%H:%M:%S%z')
    except Exception:
        return str(ts)

def firefox_time(ts):
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts / 1_000_000, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%dT%H:%M:%S%z')
    except Exception:
        return str(ts)

def safari_time(ts):
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts + MAC_EPOCH_DIFF, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%dT%H:%M:%S%z')
    except Exception:
        return str(ts)

# ──────────────────────────────────────────────────────────────────────────────
# PRIVACY ENGINE
# ──────────────────────────────────────────────────────────────────────────────
class PrivacyEngine:
    """
    Analyses a URL and title, returns a sanitised event dict.
    Raw URL and title are NEVER stored — only hashes + redacted forms.
    """

    def sha256(self, value: str) -> str:
        return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()

    def _redact_query(self, query: str):
        """
        Replace values of known-sensitive parameter names with ***REDACTED***.
        Replace high-entropy values in other parameters with ***MASKED***.
        Returns (redacted_query_string, list_of_sensitive_types_found)
        """
        if not query:
            return query, []
        found_types = []
        params = parse_qs(query, keep_blank_values=True)
        out = {}
        for k, vals in params.items():
            k_lower = k.lower().strip()
            if k_lower in SENSITIVE_PARAMS:
                out[k] = ["***REDACTED***"]
                # classify what kind of sensitive param this is
                if k_lower in {"token", "access_token", "refresh_token", "id_token", "bearer", "jwt"}:
                    found_types.append("auth_token")
                elif k_lower in {"api_key", "apikey", "api-key", "key", "x-api-key"}:
                    found_types.append("api_key")
                elif k_lower in {"session", "session_id", "sessionid", "sid", "sess", "ssid", "cookie"}:
                    found_types.append("session_id")
                elif k_lower in {"code", "auth_code", "authorization_code", "oauth_token",
                                 "oauth_verifier", "saml_response", "nonce", "state", "csrf", "csrftoken", "_token"}:
                    found_types.append("auth_code")
                elif k_lower in {"reset", "reset_token", "reset_key", "recovery_token",
                                 "magic", "magic_link", "logintoken"}:
                    found_types.append("password_reset")
                elif k_lower in {"password", "passwd", "pwd", "secret", "client_secret"}:
                    found_types.append("credential")
                else:
                    found_types.append("token")
            else:
                # check for email addresses in value
                new_vals = []
                for v in vals:
                    if EMAIL_IN_QUERY.search(v):
                        new_vals.append("***EMAIL-REDACTED***")
                        found_types.append("email")
                    elif HIGH_ENTROPY_PATTERN.search(v):
                        new_vals.append("***MASKED***")
                        found_types.append("token")
                    else:
                        new_vals.append(v)
                out[k] = new_vals
        redacted_qs = "&".join(
            f"{k}={v}" for k, vs in out.items() for v in vs
        )
        return redacted_qs, found_types

    def _redact_path(self, path: str):
        """
        Replace path segments that look like tokens (32+ alnum chars) with ***MASKED***.
        Returns (redacted_path, list_of_types_found)
        """
        found_types = []
        segments = path.split('/')
        new_segs = []
        for seg in segments:
            if HIGH_ENTROPY_PATTERN.fullmatch(seg):
                new_segs.append("***MASKED***")
                found_types.append("token")
            else:
                new_segs.append(seg)
        return '/'.join(new_segs), found_types

    def _redact_title(self, title: str):
        """
        Redact email addresses and token-like strings in page titles.
        """
        if not title:
            return title
        result = EMAIL_IN_QUERY.sub("***EMAIL***", title)
        result = HIGH_ENTROPY_PATTERN.sub("***TOKEN***", result)
        return result

    def analyse(self, url: str, title: str) -> dict:
        """
        Main entry point. Returns a privacy-safe event dict.
        Never returns raw URL or raw title.
        """
        url = url or ""
        title = title or ""

        # Compute hashes first before any modification
        url_hash   = self.sha256(url)
        title_hash = self.sha256(title)

        sensitive_detected = False
        sensitive_types    = []
        risk_category      = "normal_visit"

        parsed = None
        domain = "unknown"
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or "unknown"
        except Exception:
            pass

        if not parsed:
            return {
                "sensitive_detected": False,
                "sensitive_type":     "none",
                "risk_category":      "parse_error",
                "risk_score":         1,
                "url_redacted":       "***PARSE-ERROR***",
                "url_hash":           url_hash,
                "title_redacted":     self._redact_title(title),
                "title_hash":         title_hash,
                "domain":             "unknown",
            }

        # --- Path analysis ---
        path = parsed.path or ""
        path_redacted, path_types = self._redact_path(path)
        sensitive_types.extend(path_types)

        # Check for sensitive path patterns
        for pattern, ptype in SENSITIVE_PATH_PATTERNS:
            if pattern.search(path):
                sensitive_types.append(ptype)
                if ptype not in ("file_download",):
                    risk_category = ptype

        # --- Query string analysis ---
        qs = parsed.query or ""
        qs_redacted, qs_types = self._redact_query(qs)
        sensitive_types.extend(qs_types)

        # --- Full URL checks ---
        if CREDENTIAL_PAGE_PATTERNS.search(path):
            sensitive_types.append("credential_page")
            risk_category = "credential_page"

        if ANONYMIZER_PATTERNS.search(domain):
            sensitive_types.append("anonymizer")
            risk_category = "anonymizer"

        if CLOUD_STORAGE_PATTERNS.search(domain):
            sensitive_types.append("cloud_storage")
            if risk_category == "normal_visit":
                risk_category = "cloud_storage"

        # --- Title checks ---
        title_redacted = self._redact_title(title)

        # --- Build redacted URL ---
        try:
            redacted_url = urlunparse((
                parsed.scheme,
                domain,
                path_redacted,
                parsed.params,
                qs_redacted,
                ""  # fragment stripped — can contain tokens
            ))
        except Exception:
            redacted_url = f"{parsed.scheme}://{domain}/***REDACTED***"

        # Deduplicate and pick primary type
        sensitive_types = list(dict.fromkeys(t for t in sensitive_types if t))
        sensitive_detected = len(sensitive_types) > 0

        # Primary type = highest risk
        primary_type = "none"
        best_score   = 0
        for t in sensitive_types:
            s = RISK_SCORES.get(t, 3)
            if s > best_score:
                best_score   = s
                primary_type = t

        # Final risk score
        risk_score = max(RISK_SCORES.get(primary_type, 3),
                         RISK_SCORES.get(risk_category, 3))
        if not sensitive_detected:
            risk_score = 3
            risk_category = "normal_visit"
            primary_type  = "none"

        return {
            "sensitive_detected": sensitive_detected,
            "sensitive_type":     primary_type,
            "all_sensitive_types": sensitive_types,
            "risk_category":      risk_category,
            "risk_score":         risk_score,
            "url_redacted":       redacted_url,
            "url_hash":           url_hash,
            "title_redacted":     title_redacted,
            "title_hash":         title_hash,
            "domain":             domain,
        }


# ──────────────────────────────────────────────────────────────────────────────
# MAIN MONITOR CLASS
# ──────────────────────────────────────────────────────────────────────────────
class BrowserPrivacyMonitor:

    def __init__(self):
        self.os_type       = platform.system()
        self.hostname      = socket.gethostname()
        self.user_home     = Path.home()
        self.install_dir   = self._get_install_dir()
        self.log_path      = self.install_dir / LOG_FILE_NAME
        self.state_path    = self.install_dir / ".browser_privacy_state.json"
        self.state         = self._load_state()
        self.scan_interval = self._load_interval()
        self.privacy       = PrivacyEngine()
        self._setup_logging()
        self._safari_schema_logged = False

    # ── install dir ───────────────────────────────────────────────────────────
    def _get_install_dir(self):
        if self.os_type == "Windows":
            path = Path("C:/BrowserPrivacyMonitor")
        elif self.os_type == "Darwin":
            path = Path.home() / ".browser-privacy-monitor"
        else:
            path = Path("/root/.browser-privacy-monitor")
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ── interval ─────────────────────────────────────────────────────────────
    def _load_interval(self):
        cfg_path = self.install_dir / CONFIG_FILE_NAME
        try:
            with open(cfg_path, 'r', encoding='utf-8-sig') as f:
                cfg = json.load(f)
                return int(cfg.get("scan_interval_seconds", DEFAULT_INTERVAL))
        except Exception:
            return DEFAULT_INTERVAL

    # ── state ─────────────────────────────────────────────────────────────────
    def _load_state(self):
        try:
            if self.state_path.exists():
                with open(self.state_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_state(self):
        try:
            with open(self.state_path, 'w', encoding='utf-8') as f:
                json.dump(self.state, f)
        except Exception:
            pass

    # ── logging (JSON lines to file, syslog-style for Wazuh) ─────────────────
    def _setup_logging(self):
        """
        Write JSON lines to log file.
        Format: <syslog-header> browser-privacy-monitor: <JSON>
        Wazuh localfile picks this up with log_format json.
        """
        for h in logging.root.handlers[:]:
            logging.root.removeHandler(h)

        self.raw_logger = logging.getLogger("bpm_raw")
        self.raw_logger.setLevel(logging.INFO)
        self.raw_logger.propagate = False
        for h in self.raw_logger.handlers[:]:
            self.raw_logger.removeHandler(h)

        fh = logging.FileHandler(str(self.log_path), encoding='utf-8')
        fh.setLevel(logging.INFO)
        # Plain formatter — we control JSON structure ourselves
        fh.setFormatter(logging.Formatter("%(message)s"))
        self.raw_logger.addHandler(fh)

    def _write_event(self, event: dict):
        """Emit a single JSON line to the log file."""
        self.raw_logger.info(json.dumps(event, ensure_ascii=False))

    def _make_base_event(self, username: str, browser: str, profile: str, ts: str) -> dict:
        return {
            "integration":    "browser-privacy-monitor",
            "event_type":     "browser_visit",
            "version":        VERSION,
            "timestamp":      ts,
            "endpoint":       self.hostname,
            "platform":       self.os_type,
            "user":           username,
            "browser":        browser,
            "browser_profile": profile,
        }

    # ── browser profile discovery (inherited from Phase 2) ───────────────────
    def _find_profiles(self):
        profiles = []
        if self.os_type == "Windows":
            self._find_windows_profiles(profiles)
        elif self.os_type == "Darwin":
            self._find_macos_profiles(profiles)
        else:
            self._find_linux_profiles(profiles)
        return profiles

    def _add_chrome_profile(self, profiles, base_dir, username, browser_name):
        if not base_dir.exists():
            return
        for p in base_dir.iterdir():
            if p.is_dir() and (p.name.startswith("Profile") or p.name == "Default"):
                db = p / "History"
                if db.exists():
                    profiles.append({"kind": "chrome", "db": db, "browser": browser_name,
                                     "username": username, "profile": p.name})

    def _find_windows_profiles(self, profiles):
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
            i = 0
            while True:
                try:
                    sid   = winreg.EnumKey(key, i)
                    i += 1
                    subk  = winreg.OpenKey(key, sid)
                    path, _ = winreg.QueryValueEx(subk, "ProfileImagePath")
                    udir  = Path(os.path.expandvars(path))
                    uname = udir.name
                    udata = udir / "AppData" / "Local"
                    # Chrome
                    self._add_chrome_profile(profiles, udata / "Google/Chrome/User Data", uname, "Chrome")
                    self._add_chrome_profile(profiles, udata / "Microsoft/Edge/User Data", uname, "Edge")
                    self._add_chrome_profile(profiles, udata / "BraveSoftware/Brave-Browser/User Data", uname, "Brave")
                    self._add_chrome_profile(profiles, udata / "Opera Software/Opera Stable", uname, "Opera")
                    self._add_chrome_profile(profiles, udata / "Opera Software/Opera GX Stable", uname, "OperaGX")
                    self._add_chrome_profile(profiles, udata / "Vivaldi/User Data", uname, "Vivaldi")
                    # Firefox
                    ff_base = udir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
                    if ff_base.exists():
                        for pp in ff_base.iterdir():
                            db = pp / "places.sqlite"
                            if db.exists():
                                profiles.append({"kind": "firefox", "db": db, "browser": "Firefox",
                                                 "username": uname, "profile": pp.name})
                except OSError:
                    break
        except Exception:
            pass

    def _find_linux_profiles(self, profiles):
        import pwd
        for pw in pwd.getpwall():
            uname = pw.pw_name
            udir  = Path(pw.pw_dir)
            if not udir.exists() or pw.pw_uid < 1000:
                continue
            config = udir / ".config"
            self._add_chrome_profile(profiles, config / "google-chrome",         uname, "Chrome")
            self._add_chrome_profile(profiles, config / "chromium",               uname, "Chromium")
            self._add_chrome_profile(profiles, config / "microsoft-edge",         uname, "Edge")
            self._add_chrome_profile(profiles, config / "BraveSoftware/Brave-Browser", uname, "Brave")
            self._add_chrome_profile(profiles, config / "opera",                  uname, "Opera")
            self._add_chrome_profile(profiles, config / "vivaldi",                uname, "Vivaldi")
            # Snap Firefox
            for snap_path in [
                udir / "snap/firefox/common/.mozilla/firefox",
                udir / ".mozilla/firefox",
            ]:
                if snap_path.exists():
                    for pp in snap_path.iterdir():
                        if pp.is_dir() and ".default" in pp.name:
                            db = pp / "places.sqlite"
                            if db.exists():
                                profiles.append({"kind": "firefox", "db": db, "browser": "Firefox",
                                                 "username": uname, "profile": pp.name})
                    break
            # root Firefox
        # Also check /root
        root_ff = Path("/root/.mozilla/firefox")
        if root_ff.exists():
            for pp in root_ff.iterdir():
                if pp.is_dir() and ".default" in pp.name:
                    db = pp / "places.sqlite"
                    if db.exists():
                        profiles.append({"kind": "firefox", "db": db, "browser": "Firefox",
                                         "username": "root", "profile": pp.name})

    def _find_macos_profiles(self, profiles):
        users_dir = Path("/Users")
        if not users_dir.exists():
            return
        for udir in users_dir.iterdir():
            if not udir.is_dir() or udir.name.startswith('.'):
                continue
            uname  = udir.name
            ulibs  = udir / "Library"
            app_support = ulibs / "Application Support"
            self._add_chrome_profile(profiles, app_support / "Google/Chrome",       uname, "Chrome")
            self._add_chrome_profile(profiles, app_support / "Microsoft Edge",       uname, "Edge")
            self._add_chrome_profile(profiles, app_support / "BraveSoftware/Brave-Browser", uname, "Brave")
            self._add_chrome_profile(profiles, app_support / "Vivaldi",              uname, "Vivaldi")
            # Firefox
            ff_base = ulibs / "Application Support/Firefox/Profiles"
            if ff_base.exists():
                for pp in ff_base.iterdir():
                    db = pp / "places.sqlite"
                    if db.exists():
                        profiles.append({"kind": "firefox", "db": db, "browser": "Firefox",
                                         "username": uname, "profile": pp.name})
            # Safari
            safari_db = ulibs / "Safari/History.db"
            if safari_db.exists():
                profiles.append({"kind": "safari", "db": safari_db, "browser": "Safari",
                                 "username": uname, "profile": "Default"})

    # ── Safari WAL copy ───────────────────────────────────────────────────────
    def _copy_safari_db(self, src_db: Path, tmp_dir: Path) -> Path:
        journal_mode = "delete"
        try:
            probe = sqlite3.connect(f"file:{src_db}?mode=ro", uri=True)
            row   = probe.execute("PRAGMA journal_mode").fetchone()
            probe.close()
            if row:
                journal_mode = row[0].lower()
        except Exception:
            pass
        dst = tmp_dir / "History.db"
        shutil.copy2(src_db, dst)
        if journal_mode == "wal":
            for ext in ("-wal", "-shm", "-lock"):
                sidecar = Path(str(src_db) + ext)
                if sidecar.exists():
                    try:
                        shutil.copy2(sidecar, tmp_dir / ("History.db" + ext))
                    except Exception:
                        pass
            try:
                ckpt = sqlite3.connect(str(dst))
                ckpt.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                ckpt.close()
            except Exception:
                pass
        return dst

    # ── history processing with privacy engine ────────────────────────────────
    def _process_history(self, profile):
        state_key      = f"hist_{profile['username']}_{profile['browser']}_{profile['profile']}"
        last_scan_time = self.state.get(state_key, 0)

        safe_key = state_key.replace('/', '_').replace(' ', '_')
        tmp_dir  = Path(tempfile.mkdtemp(prefix="bpm_"))
        tmp_db   = tmp_dir / f"{safe_key}.sqlite"

        try:
            if profile["kind"] == "safari":
                tmp_db = self._copy_safari_db(profile["db"], tmp_dir)
            else:
                shutil.copy2(profile["db"], tmp_db)
        except PermissionError:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return

        conn    = None
        new_max = last_scan_time
        try:
            uri  = f"file:{tmp_db}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cur  = conn.cursor()

            if profile["kind"] == "chrome":
                cur.execute(
                    "SELECT last_visit_time, url, title FROM urls "
                    "WHERE last_visit_time > ? ORDER BY last_visit_time ASC",
                    (last_scan_time,)
                )
            elif profile["kind"] == "firefox":
                cur.execute(
                    "SELECT h.visit_date, p.url, p.title "
                    "FROM moz_historyvisits h "
                    "JOIN moz_places p ON h.place_id = p.id "
                    "WHERE h.visit_date > ? ORDER BY h.visit_date ASC",
                    (last_scan_time,)
                )
            elif profile["kind"] == "safari":
                cur.execute(
                    "SELECT v.visit_time, i.url, v.title "
                    "FROM history_visits v "
                    "JOIN history_items i ON v.history_item = i.id "
                    "WHERE v.visit_time > ? ORDER BY v.visit_time ASC",
                    (last_scan_time,)
                )

            for (raw_time, url, title) in cur.fetchall():
                if raw_time > new_max:
                    new_max = raw_time

                if profile["kind"] == "chrome":
                    readable = chrome_time(raw_time)
                elif profile["kind"] == "firefox":
                    readable = firefox_time(raw_time)
                else:
                    readable = safari_time(raw_time)

                clean_title = (title or "No Title").replace('\n', ' ').replace('\r', '')

                # ── PRIVACY ENGINE — analyse before any log write ──────────
                privacy_result = self.privacy.analyse(url, clean_title)

                # ── BUILD SAFE EVENT (no raw URL, no raw title) ───────────
                event = self._make_base_event(
                    profile['username'],
                    profile['browser'],
                    profile['profile'],
                    readable
                )
                event.update({
                    "domain":             privacy_result["domain"],
                    "sensitive_detected": privacy_result["sensitive_detected"],
                    "sensitive_type":     privacy_result["sensitive_type"],
                    "risk_category":      privacy_result["risk_category"],
                    "risk_score":         privacy_result["risk_score"],
                    "url_redacted":       privacy_result["url_redacted"],
                    "url_hash":           privacy_result["url_hash"],
                    "title_redacted":     privacy_result["title_redacted"],
                    "title_hash":         privacy_result["title_hash"],
                })

                self._write_event(event)

        except Exception:
            pass
        finally:
            if conn:
                conn.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

        self.state[state_key] = new_max

    # ── main loop ─────────────────────────────────────────────────────────────
    def run(self):
        self._write_event({
            "integration": "browser-privacy-monitor",
            "event_type":  "service_started",
            "version":     VERSION,
            "endpoint":    self.hostname,
            "platform":    self.os_type,
            "scan_interval_seconds": self.scan_interval,
            "timestamp":   datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z'),
        })
        try:
            while True:
                profiles = self._find_profiles()
                for profile in profiles:
                    self._process_history(profile)
                self._save_state()
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            self._write_event({
                "integration": "browser-privacy-monitor",
                "event_type":  "service_stopped",
                "endpoint":    self.hostname,
                "timestamp":   datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z'),
            })


if __name__ == "__main__":
    BrowserPrivacyMonitor().run()
