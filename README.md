# Wazuh Browser Privacy Monitor — Phase 3

**Privacy-safe browser telemetry for Wazuh SIEM**  
*Detect sensitive browsing activity. Never expose the sensitive value itself.*

> **Design Principle:** Collect raw locally → detect locally → store centrally **only in redacted form.**  
> Raw secrets never reach the dashboard, indexer, or log file that Wazuh reads.

**Author:** Ram Kumar G · [IT Fortress](https://github.com/Ramkumar2545)  
**Phase:** 3 (Privacy-Safe Telemetry Edition)  
**Platforms:** Windows · Linux · macOS  
**Browsers:** Chrome · Edge · Brave · Firefox · Opera · OperaGX · Vivaldi · Chromium · Safari

---

## Why Phase 3?

Phase 1 and Phase 2 collected full browser history events and forwarded them to Wazuh.  
This gave full visibility but introduced **exposure risk**:

| Risk | Example |
|------|---------|
| Password reset tokens in full URL | `https://app.com/reset?token=eyJhbGci...` |
| OAuth auth codes | `https://portal.com/callback?code=4/P7q7W91` |
| Session IDs | `?sessionid=abc123xyz789...` |
| API keys | `?api_key=sk-live-...` |
| Email in query | `?email=user@company.com` |
| Magic login links | `https://app.com/magic?token=...` |

Once those values reach the Wazuh indexer or dashboard, **any analyst, admin, or dashboard user** can read them.

**Phase 3 solves this at the endpoint** — the collector detects and redacts sensitive values _before_ writing to the log file that Wazuh ingests.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         ENDPOINT                                 │
│                                                                  │
│  Browser SQLite DB ──► Privacy Engine ──► Redacted JSON Log      │
│    (raw URL stays       ┌──────────────────────────┐             │
│     in SQLite only)     │  1. Parse URL             │             │
│                         │  2. Detect sensitive params│             │
│                         │  3. Mask/redact values    │             │
│                         │  4. Hash full URL/title   │             │
│                         │  5. Compute risk_score    │             │
│                         └──────────────────────────┘             │
│                                    │                             │
│                    browser_privacy.log (JSON lines)              │
│                    [NO raw URLs · NO tokens · NO passwords]      │
└──────────────────────────────────┬───────────────────────────────┘
                                   │  Wazuh Agent (localfile json)
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                       WAZUH MANAGER                              │
│                                                                  │
│  Decoder (JSON auto-parse) ──► Rules (901000–901030)             │
│                                    │                             │
│  Alerts contain:                   │                             │
│    ✅ domain, browser, user        │                             │
│    ✅ risk_category, risk_score    │                             │
│    ✅ sensitive_type               │                             │
│    ✅ url_redacted (masked)        │                             │
│    ✅ url_hash (SHA-256 only)      │                             │
│    ❌ Full URL                     │                             │
│    ❌ Query strings                │                             │
│    ❌ Tokens / session IDs         │                             │
└──────────────────────────────────┬───────────────────────────────┘
                                   │  Ingest Pipeline (Layer 2)
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                    WAZUH INDEXER / DASHBOARD                     │
│                                                                  │
│  Ingest pipeline drops: url, title, raw_url (if accidentally set)│
│  Dashboard shows: domain · browser · user · risk_category        │
│  Never shows: passwords · tokens · session IDs · API keys        │
└──────────────────────────────────────────────────────────────────┘
```

---

## Protection Layers

### Layer 1 — Endpoint Redaction (collector)

The collector's `PrivacyEngine` runs before any log write:

| What it detects | How it protects |
|-----------------|-----------------|
| Named sensitive params (`token=`, `api_key=`, `session=`, etc.) | Value replaced with `***REDACTED***` |
| High-entropy path segments (32+ char tokens) | Replaced with `***MASKED***` |
| Email addresses in query strings | Replaced with `***EMAIL-REDACTED***` |
| URL fragment (`#token=...`) | Stripped entirely |
| Auth/OAuth callback paths | Classified, path preserved, no value leakage |
| Reset-password / magic-link paths | Classified, path preserved |

The full URL and title are **hashed (SHA-256)** for correlation. Hash is one-way — no analyst can reverse it.

### Layer 2 — Indexer Pipeline (`wazuh/pipelines/`)

An OpenSearch ingest pipeline:
- Drops `url`, `full_url`, `raw_url`, `title`, `page_title` if they accidentally appear
- Strips URL fragments at index time
- Detects high-entropy strings that slipped past Layer 1
- Normalises `risk_score` and `sensitive_detected` field types

### Layer 3 — Dashboard Access Control

The dashboard should only display:
- `domain` · `browser` · `user` · `endpoint`
- `risk_category` · `sensitive_type` · `risk_score`
- `url_redacted` (masked form)

Field-level security in Wazuh Dashboard: exclude `url_hash` and `title_hash` from non-admin roles (hash-only fields for analyst correlation, not general display).

---

## Event Schema

Every event written to `browser_privacy.log` is a single JSON line:

```json
{
  "integration":        "browser-privacy-monitor",
  "event_type":         "browser_visit",
  "version":            "1.0.0",
  "timestamp":          "2026-04-17T16:05:32+0530",
  "endpoint":           "WIN-DESKTOP01",
  "platform":           "Windows",
  "user":               "john.doe",
  "browser":            "Chrome",
  "browser_profile":    "Default",
  "domain":             "portal.company.com",
  "sensitive_detected": true,
  "sensitive_type":     "password_reset",
  "risk_category":      "password_reset",
  "risk_score":         10,
  "url_redacted":       "https://portal.company.com/reset?token=***REDACTED***",
  "url_hash":           "a3f8c2e...sha256-of-full-url...",
  "title_redacted":     "Reset Your Password",
  "title_hash":         "b9d1f4a...sha256-of-title..."
}
```

### What is NEVER logged

| Sensitive value | Protection applied |
|-----------------|--------------------|
| `?token=eyJhbGci...` | Param value → `***REDACTED***` |
| `?session_id=abc123` | Param value → `***REDACTED***` |
| `?api_key=sk-live-xxx` | Param value → `***REDACTED***` |
| `/reset/eyJhbGci.../confirm` | Path segment → `***MASKED***` |
| `?email=user@corp.com` | Value → `***EMAIL-REDACTED***` |
| `#access_token=...` | Fragment stripped entirely |
| Full page title with PII | Hashed → `title_hash` only |

---

## Sensitive Type Classification

| `sensitive_type` | `risk_score` | Description |
|-----------------|--------------|-------------|
| `auth_token` | 10 | Bearer / JWT / access token in URL |
| `session_id` | 10 | Session cookie ID exposed in URL |
| `password_reset` | 10 | Reset-password link/token |
| `magic_link` | 10 | Magic login link token |
| `auth_code` | 9 | OAuth code / SAML response / SSO callback |
| `api_key` | 9 | API key parameter detected |
| `credential` | 8 | Password or client_secret in URL |
| `credential_page` | 8 | Login / MFA / 2FA / verify page |
| `token` | 8 | High-entropy string (unclassified) |
| `internal_doc` | 6 | Export / download / admin page |
| `email` | 6 | Email address in query parameter |
| `file_download` | 7 | Dangerous file extension (exe, ps1, etc.) |
| `anonymizer` | 7 | TOR / VPN / anonymizer site |
| `cloud_storage` | 5 | Google Drive / Dropbox / OneDrive visit |
| `personal_query` | 5 | Unsubscribe / personal query parameter |
| `none` | 3 | Normal visit, no sensitive data |

---

## Wazuh Rules

| Rule ID | Level | Trigger |
|---------|-------|---------|
| 901000 | 2 | Service started |
| 901001 | 2 | Service stopped |
| 901010 | 3 | Every browser visit (base parent) |
| 901011 | 3 | Normal visit, no sensitive data |
| 901012 | 7 | Sensitive data detected (any type) |
| 901013 | **12** | Auth token or session ID in URL |
| 901014 | **12** | Password reset / magic link |
| 901015 | 10 | OAuth / auth code callback |
| 901016 | 10 | API key in URL |
| 901017 | 10 | Credential or login page |
| 901018 | 7 | Email address in URL query |
| 901019 | 8 | Internal document / export URL |
| 901020 | 7 | Cloud storage visit |
| 901021 | 9 | Anonymizer / TOR / VPN site |
| 901022 | 9 | Dangerous file download |
| 901023 | 8 | High-entropy token in URL path |
| 901030 | **12** | risk_score ≥ 9 (composite critical) |

---

## Installation

### Linux (Ubuntu / Debian)

```bash
# One-line install (5-minute interval)
sudo bash -c "$(curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/installers/linux-installer.sh)"

# Custom interval (300 seconds = 5 min)
sudo bash linux-installer.sh --interval 300

# Uninstall
sudo bash linux-installer.sh --uninstall
```

**What gets installed:**
```
/opt/browser-privacy-monitor/browser-privacy-monitor.py
/root/.browser-privacy-monitor/browser_privacy.log      ← Wazuh reads this
/root/.browser-privacy-monitor/.browser_privacy_config.json
/etc/systemd/system/browser-privacy-monitor.service
```

**Verify:**
```bash
systemctl status browser-privacy-monitor
tail -f /root/.browser-privacy-monitor/browser_privacy.log | python3 -m json.tool
```

---

### Windows (PowerShell as Admin)

```powershell
# Allow execution for this session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Install (5-minute interval default)
.\installers\windows-installer.ps1

# Custom interval
.\installers\windows-installer.ps1 -Interval 300

# Uninstall
.\installers\windows-installer.ps1 -Uninstall
```

**What gets installed:**
```
C:\BrowserPrivacyMonitor\browser-privacy-monitor.py
C:\BrowserPrivacyMonitor\browser_privacy.log      ← Wazuh reads this
C:\BrowserPrivacyMonitor\.browser_privacy_config.json
Task Scheduler → "BrowserPrivacyMonitor" (runs as SYSTEM)
```

**Verify:**
```powershell
Get-ScheduledTask -TaskName "BrowserPrivacyMonitor"
Get-Content "C:\BrowserPrivacyMonitor\browser_privacy.log" -Tail 10 -Wait
```

---

## Wazuh Manager Setup

### 1. Deploy decoder

Copy to Wazuh manager:
```bash
cp wazuh/decoders/0320-browser_privacy_decoder.xml /var/ossec/etc/decoders/
```

> **Note:** If using `log_format=json` (recommended), the decoder file is documentation only. Wazuh auto-parses JSON fields.

### 2. Deploy rules

```bash
cp wazuh/rules/0320-browser_privacy_rules.xml /var/ossec/etc/rules/
```

### 3. Validate and restart

```bash
/var/ossec/bin/wazuh-logtest -V
systemctl restart wazuh-manager
```

### 4. Test with logtest

```bash
echo '{"integration":"browser-privacy-monitor","event_type":"browser_visit","user":"testuser","browser":"Chrome","endpoint":"test-host","domain":"accounts.google.com","sensitive_detected":true,"sensitive_type":"auth_code","risk_category":"auth_code","risk_score":9,"url_redacted":"https://accounts.google.com/o/oauth2/callback?code=***REDACTED***","url_hash":"abc123","title_redacted":"Sign in","title_hash":"def456","timestamp":"2026-04-17T10:00:00+0530","platform":"Linux","browser_profile":"Default"}' | /var/ossec/bin/wazuh-logtest
```

---

## Indexer Pipeline (Layer 2)

```bash
# Install pipeline on Wazuh Indexer
curl -u admin:YOUR_PASSWORD -k \
  -X PUT "https://INDEXER_IP:9200/_ingest/pipeline/browser-privacy-monitor" \
  -H "Content-Type: application/json" \
  --data-binary @wazuh/pipelines/browser_privacy_pipeline.json

# Apply as default pipeline for wazuh-alerts index
curl -u admin:YOUR_PASSWORD -k \
  -X PUT "https://INDEXER_IP:9200/wazuh-alerts-4.x-*/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.default_pipeline": "browser-privacy-monitor"}'
```

---

## Dashboard Visualisations (Recommended)

Create these panels in Wazuh Dashboard:

| Panel | Visualization | Fields |
|-------|---------------|--------|
| Risk Heatmap | Heat map by `user` × `risk_category` | `user`, `risk_category`, count |
| Sensitive Events Timeline | Bar chart over time | `sensitive_type`, timestamp |
| Top Sensitive Domains | Data table | `domain`, `sensitive_type`, count |
| Risk Score Distribution | Pie chart | `risk_score` |
| Browser by User | Table | `browser`, `user`, `endpoint` |
| Critical Alerts (score ≥ 9) | Alert table | All fields except `url_hash`, `title_hash` |

**Field-level security (Wazuh Dashboard roles):**
- Standard analyst: exclude `url_hash`, `title_hash`
- SOC lead: full access to all fields
- Admin: full access + indexer pipeline management

---

## Comparison: Phase 2 vs Phase 3

| Feature | Phase 2 | Phase 3 |
|---------|---------|---------|
| Full URL in log | ✅ Yes | ❌ No — hashed only |
| Query string values | ✅ Raw | ❌ Redacted |
| Token/session in log | ✅ Visible | ❌ `***REDACTED***` |
| Email in log | ✅ Raw | ❌ `***EMAIL-REDACTED***` |
| Sensitive detection | ✅ Rules-only | ✅ Endpoint + Rules |
| risk_score field | ❌ No | ✅ 1-10 |
| sensitive_type field | ❌ No | ✅ 15 types |
| url_hash (correlation) | ❌ No | ✅ SHA-256 |
| Ingest pipeline | ❌ No | ✅ Layer 2 protection |
| Dashboard spy risk | ⚠️ High | ✅ Eliminated |

---

## Related Projects

| Project | Description |
|---------|-------------|
| [wazuh-browser-history-monitoring](https://github.com/Ramkumar2545/wazuh-browser-history-monitoring) | Phase 1 — Multi-browser history with Wazuh rules |
| [browsing-monitoring-history-phases-2](https://github.com/Ramkumar2545/browsing-monitoring-history-phases-2) | Phase 2 — Configurable intervals, full browser support |
| [opencti-wazuh-connector-public](https://github.com/Ramkumar2545/opencti-wazuh-connector-public) | OpenCTI ↔ Wazuh integration for threat intelligence |

---

## License

MIT — see [LICENSE](LICENSE)

---

*IT Fortress by Ram Kumar G — Building privacy-first security monitoring*
