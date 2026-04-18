# Wazuh Browser Privacy Monitor — Phase 3

> **Privacy-safe browser telemetry for Wazuh SIEM**
> Detect sensitive browsing activity. Never expose the sensitive value itself.

**Author:** Ram Kumar G · [IT Fortress](https://github.com/Ramkumar2545)
**Phase:** 3 — Privacy-Safe Telemetry Edition
**Platforms:** Windows · Linux · macOS
**Browsers:** Chrome · Edge · Brave · Firefox · Opera · OperaGX · Vivaldi · Chromium · Safari (macOS)

---

## Design Principle

> **Collect raw locally → Detect locally → Store centrally only in redacted form**

Raw URLs, tokens, session IDs, API keys, passwords, and email addresses are **never written** to the log file that Wazuh reads. The endpoint redacts everything before forwarding. The Wazuh dashboard only ever sees masked evidence — not the secret itself.

---

## One-Line Installation

### Linux

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.sh | sudo bash
```

### macOS

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.sh | bash
```

### Windows (Admin PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.ps1' | iex"
```

> The installer will **interactively ask you to choose a scan interval** during installation.

---

## Scan Interval Options

When you run the installer, you will see this prompt:

```
[2] Select scan interval (how often to check browser history):
     1)  1  minute   (high I/O — testing only)
     2)  5  minutes
     3)  10 minutes
     4)  20 minutes
     5)  30 minutes  (recommended)
     6)  60 minutes / 1 hour
     7)  2  hours
     8)  6  hours
     9)  12 hours
    10)  24 hours    (once per day)

    Enter choice [1-10] (default: 5 = 30 minutes):
```

| Choice | Interval | Use case |
|--------|----------|----------|
| 1 | 1 minute | Testing / high-visibility environments |
| 2 | 5 minutes | Active monitoring |
| 3 | 10 minutes | Balanced monitoring |
| 4 | 20 minutes | Standard endpoint monitoring |
| **5** | **30 minutes** | **Recommended — low I/O, good coverage** |
| 6 | 1 hour | Low-overhead environments |
| 7 | 2 hours | Compliance/audit use |
| 8 | 6 hours | Daily summary |
| 9 | 12 hours | Twice-daily sweep |
| 10 | 24 hours | Once-per-day audit |

The selected interval is saved to the config file on the endpoint and read by the service on every restart. You can change it anytime by editing the config or re-running the installer.

**Config file locations:**

| OS | Config path |
|----|------------|
| Linux | `/root/.browser-privacy-monitor/.browser_privacy_config.json` |
| macOS | `~/.browser-privacy-monitor/.browser_privacy_config.json` |
| Windows | `C:\BrowserPrivacyMonitor\.browser_privacy_config.json` |

```json
{
  "scan_interval_seconds": 1800,
  "scan_interval_label": "30m",
  "version": "1.0.0"
}
```

---

## What Gets Installed

### Linux

| Item | Location |
|------|----------|
| Collector script | `/opt/browser-privacy-monitor/browser-privacy-monitor.py` |
| Log file (Wazuh reads this) | `/root/.browser-privacy-monitor/browser_privacy.log` |
| Config file | `/root/.browser-privacy-monitor/.browser_privacy_config.json` |
| systemd service | `/etc/systemd/system/browser-privacy-monitor.service` |
| Wazuh localfile config | Auto-added to `/var/ossec/etc/ossec.conf` |

### macOS

| Item | Location |
|------|----------|
| Collector script | `~/.browser-privacy-monitor/browser-privacy-monitor.py` |
| Log file (Wazuh reads this) | `~/.browser-privacy-monitor/browser_privacy.log` |
| Config file | `~/.browser-privacy-monitor/.browser_privacy_config.json` |
| LaunchAgent | `~/Library/LaunchAgents/com.ramkumar.browser-privacy-monitor.plist` |
| Wazuh localfile config | Auto-added to `/Library/Ossec/etc/ossec.conf` |

### Windows

| Item | Location |
|------|----------|
| Collector script | `C:\BrowserPrivacyMonitor\browser-privacy-monitor.py` |
| Log file (Wazuh reads this) | `C:\BrowserPrivacyMonitor\browser_privacy.log` |
| Config file | `C:\BrowserPrivacyMonitor\.browser_privacy_config.json` |
| Task Scheduler | `BrowserPrivacyMonitor` (runs as SYSTEM, AtStartup + repeat) |
| Startup shortcut | `%ProgramData%\...\StartUp\WazuhBrowserPrivacyMonitor.lnk` |
| Wazuh localfile config | Auto-added to `C:\Program Files (x86)\ossec-agent\ossec.conf` |

---

## Verify Installation

### Linux

```bash
# Check service is running
systemctl status browser-privacy-monitor

# Watch live JSON events (pretty-printed)
tail -f /root/.browser-privacy-monitor/browser_privacy.log | python3 -m json.tool

# Check journal logs
journalctl -u browser-privacy-monitor -f

# Confirm interval in first event
grep "service_started" /root/.browser-privacy-monitor/browser_privacy.log | tail -1
```

### macOS

```bash
# Check LaunchAgent
launchctl list | grep browser-privacy-monitor

# Watch live events
tail -f ~/.browser-privacy-monitor/browser_privacy.log | python3 -m json.tool

# Check error log
cat ~/.browser-privacy-monitor/error.log
```

> **macOS Only:** You must grant Full Disk Access to Python for browser history to be readable.
> System Settings → Privacy & Security → Full Disk Access → `+` → Add Python binary

### Windows

```powershell
# Check Task Scheduler
Get-ScheduledTask -TaskName "BrowserPrivacyMonitor"

# Watch live events
Get-Content "C:\BrowserPrivacyMonitor\browser_privacy.log" -Tail 20 -Wait

# Check interval in first event
Select-String "service_started" "C:\BrowserPrivacyMonitor\browser_privacy.log" | Select -Last 1
```

---

## Wazuh Manager Setup

After installing the endpoint collector, configure the Wazuh Manager:

### Step 1 — Deploy decoder

```bash
cp wazuh/decoders/0320-browser_privacy_decoder.xml /var/ossec/etc/decoders/
```

> If using `log_format=json` (default, recommended), this decoder is only needed as a syslog-relay fallback. Wazuh auto-parses JSON fields natively.

### Step 2 — Deploy rules

```bash
cp wazuh/rules/0320-browser_privacy_rules.xml /var/ossec/etc/rules/
```

### Step 3 — Validate and restart

```bash
/var/ossec/bin/wazuh-logtest -V
systemctl restart wazuh-manager
```

### Step 4 — Test with wazuh-logtest

Paste this into `/var/ossec/bin/wazuh-logtest` to verify rules fire correctly:

```
{"integration":"browser-privacy-monitor","event_type":"browser_visit","user":"john","browser":"Chrome","endpoint":"WIN-01","domain":"portal.company.com","sensitive_detected":true,"sensitive_type":"password_reset","risk_category":"password_reset","risk_score":10,"url_redacted":"https://portal.company.com/reset?token=***REDACTED***","url_hash":"abc123","title_redacted":"Reset Password","title_hash":"def456","timestamp":"2026-04-17T10:00:00+0530","platform":"Windows","browser_profile":"Default"}
```

Expected: Rule **901014** fires at **Level 12** — `CRITICAL: Password Reset / Magic Link in Browser`

---

## Wazuh localfile Config (ossec.conf)

The installer adds this block automatically. If you need to add it manually:

### Linux / macOS

```xml
<!-- BROWSER_PRIVACY_MONITOR_P3 -->
<localfile>
  <log_format>json</log_format>
  <location>/root/.browser-privacy-monitor/browser_privacy.log</location>
  <label key="integration">browser-privacy-monitor</label>
</localfile>
```

### Windows

```xml
<!-- BROWSER_PRIVACY_MONITOR_P3 -->
<localfile>
  <log_format>json</log_format>
  <location>C:\BrowserPrivacyMonitor\browser_privacy.log</location>
  <label key="integration">browser-privacy-monitor</label>
</localfile>
```

---

## Layer 2 — Indexer Ingest Pipeline

> ⚠️ **Read this carefully before applying the pipeline.**

### How it actually works in Wazuh

Wazuh uses **Filebeat** to forward alerts from the Wazuh Manager to the Wazuh Indexer (OpenSearch). Filebeat already loads its own ingest pipeline called `filebeat-7.10.2-wazuh-alerts-pipeline` which processes every alert document before it gets indexed.

The file that controls this pipeline is on the **Wazuh Manager**:
```
/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
```

**There are two valid ways to apply the privacy pipeline:**

---

### Method A — Inject into Filebeat's existing pipeline (Recommended)

This is the correct, stable way. You add the privacy processors directly into Filebeat's pipeline file on the Wazuh Manager, then reload it.

#### Step 1 — Back up the existing pipeline

```bash
cp /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json \
   /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json.bak
```

#### Step 2 — Add privacy processors to the pipeline

Open the file:
```bash
nano /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
```

Find the `"processors": [` array and add these processors **before the final `remove` processors** at the bottom of the list:

```json
{
  "gsub": {
    "field": "data.url_redacted",
    "pattern": "#.*$",
    "replacement": "#[fragment-removed]",
    "ignore_missing": true,
    "ignore_failure": true
  }
},
{
  "script": {
    "lang": "painless",
    "source": "if (ctx.data != null && ctx.data.url_redacted != null) { def url = ctx.data.url_redacted; def tokenPattern = /[A-Za-z0-9+\\/_~\\-]{64,}/; if (tokenPattern.matcher(url).find()) { ctx.data.url_redacted = '[PIPELINE-MASKED]'; ctx.data.pipeline_masked = true; } }",
    "ignore_failure": true
  }
},
{
  "remove": {
    "field": ["data.url", "data.full_url", "data.raw_url"],
    "ignore_missing": true,
    "ignore_failure": true
  }
},
{
  "remove": {
    "field": ["data.title", "data.page_title", "data.raw_title"],
    "ignore_missing": true,
    "ignore_failure": true
  }
},
{
  "convert": {
    "field": "data.risk_score",
    "type": "integer",
    "ignore_missing": true,
    "ignore_failure": true
  }
},
{
  "convert": {
    "field": "data.sensitive_detected",
    "type": "boolean",
    "ignore_missing": true,
    "ignore_failure": true
  }
}
```

#### Step 3 — Reload the pipeline into the Indexer

```bash
filebeat setup --pipelines --modules wazuh
```

Expected output: `Loaded Ingest pipelines`

#### Step 4 — Verify the pipeline was loaded

```bash
curl -u admin:Wazuh*12345 -k \
  "https://127.0.0.1:9200/_ingest/pipeline/filebeat-7.10.2-wazuh-alerts-pipeline" \
  | python3 -m json.tool | grep -A5 "url_redacted"
```

You should see your `gsub` processor for `data.url_redacted` in the output.

---

### Method B — Register as a separate pipeline via API (Optional / Advanced)

If you want to keep the privacy pipeline completely separate from Filebeat's pipeline, you can register it as its own OpenSearch pipeline. This is optional — **Layer 1 endpoint redaction already handles 99% of protection**, so Method B is only needed if you want indexer-level enforcement as an extra guarantee.

#### Step 1 — Create clean pipeline JSON (strip comments)

Run this on the Wazuh Manager:

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/wazuh/pipelines/browser_privacy_pipeline.json \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
clean = {k: v for k, v in d.items() if not k.startswith('_')}
clean['processors'] = [{k2: v2 for k2, v2 in p.items() if k2 != '_comment'} for p in clean['processors']]
print(json.dumps(clean, indent=2))
" > /tmp/browser_privacy_pipeline_clean.json
```

#### Step 2 — Register on the Indexer

```bash
curl -u admin:Wazuh*12345 -k \
  -X PUT "https://127.0.0.1:9200/_ingest/pipeline/browser-privacy-monitor" \
  -H "Content-Type: application/json" \
  -d @/tmp/browser_privacy_pipeline_clean.json
```

Expected: `{"acknowledged": true}`

#### Step 3 — Verify it registered

```bash
curl -u admin:Wazuh*12345 -k \
  "https://127.0.0.1:9200/_ingest/pipeline/browser-privacy-monitor" \
  | python3 -m json.tool
```

#### Step 4 — Test with simulate API

```bash
curl -u admin:Wazuh*12345 -k \
  -X POST "https://127.0.0.1:9200/_ingest/pipeline/browser-privacy-monitor/_simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "docs": [{
      "_source": {
        "data": {
          "url_redacted": "https://portal.com/reset?token=eyJhbGciOiJSUz...longtoken...longertoken...",
          "sensitive_detected": "true",
          "risk_score": "10"
        }
      }
    }]
  }'
```

Expected: `url_redacted` becomes `[PIPELINE-MASKED]`, `risk_score` becomes integer `10`, `sensitive_detected` becomes boolean `true`.

> **Note on `default_pipeline`:** Applying a `default_pipeline` to `wazuh-alerts-4.x-*` index settings is possible but **not recommended** — it can interfere with Filebeat's existing pipeline and cause indexing failures. Method A (injecting into Filebeat's pipeline) is always safer.

---

### Where your Indexer address is

| Setup | Use this address |
|-------|-----------------|
| All-in-one (single node) | `https://localhost:9200` |
| Multi-node cluster | `https://<indexer-node-ip>:9200` |
| Docker Compose | Check with `docker inspect wazuh.indexer` |

Find it in your Wazuh Manager config:
```bash
grep -A3 "hosts" /etc/filebeat/filebeat.yml | head -6
```

---

### Do I need the pipeline at all?

**Honest answer:** For this project, **the pipeline is Layer 2 — a safety net, not the primary protection.**

Layer 1 (endpoint redaction) already ensures raw secrets never reach Wazuh. The pipeline adds a second line of defence in case something slips through. If you are just getting started, focus on:

1. ✅ Install the collector on endpoints (Layer 1 — the most important)
2. ✅ Deploy decoder + rules on the Wazuh Manager
3. ⬛ Apply the pipeline (Layer 2 — optional extra hardening)

You get full detection and privacy protection from Layer 1 alone.

---

## How Privacy Redaction Works

The collector's `PrivacyEngine` runs on every URL **before** writing to the log file.

### What gets redacted

| Sensitive value | What the log shows |
|-----------------|-------------------|
| `?token=eyJhbGci...` | `?token=***REDACTED***` |
| `?session_id=abc123xyz` | `?session_id=***REDACTED***` |
| `?api_key=sk-live-xxx` | `?api_key=***REDACTED***` |
| `?password=hunter2` | `?password=***REDACTED***` |
| `?email=user@corp.com` | `?email=***EMAIL-REDACTED***` |
| `/reset/eyJhbGci.../confirm` | `/reset/***MASKED***/confirm` |
| `#access_token=...` | *(fragment stripped entirely)* |
| Full URL | SHA-256 hash (`url_hash`) for correlation only |
| Full page title | SHA-256 hash (`title_hash`) — title shown only if no PII |

### Sensitive type classification

| `sensitive_type` | `risk_score` | Description |
|-----------------|:------------:|-------------|
| `auth_token` | 10 | Bearer / JWT / access token in URL |
| `session_id` | 10 | Session cookie ID exposed in URL |
| `password_reset` | 10 | Reset-password link/token |
| `magic_link` | 10 | Magic login link token |
| `auth_code` | 9 | OAuth code / SAML response / SSO callback |
| `api_key` | 9 | API key parameter detected |
| `credential` | 8 | Password or client_secret in URL |
| `credential_page` | 8 | Login / MFA / 2FA / verify page |
| `token` | 8 | High-entropy string (unclassified) |
| `file_download` | 7 | Dangerous file extension (exe, ps1, etc.) |
| `anonymizer` | 7 | TOR / VPN / anonymizer site |
| `internal_doc` | 6 | Export / download / admin page |
| `email` | 6 | Email address in query parameter |
| `cloud_storage` | 5 | Google Drive / Dropbox / OneDrive visit |
| `personal_query` | 5 | Unsubscribe / personal query parameter |
| `none` | 3 | Normal visit — no sensitive data |

---

## Event Schema (JSON)

Every event written to the log is a single JSON line:

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
  "url_hash":           "a3f8c2e1...sha256...",
  "title_redacted":     "Reset Your Password",
  "title_hash":         "b9d1f4a2...sha256..."
}
```

---

## Wazuh Rules Reference

| Rule ID | Level | Trigger |
|---------|:-----:|---------|
| 901000 | 2 | Service started (with interval label) |
| 901001 | 2 | Service stopped |
| 901010 | 3 | Every browser visit — base parent |
| 901011 | 3 | Normal visit, no sensitive data detected |
| 901012 | 7 | Sensitive data detected (any type) |
| **901013** | **12** | Auth token or session ID in URL |
| **901014** | **12** | Password reset / magic link |
| 901015 | 10 | OAuth / auth code / SAML callback |
| 901016 | 10 | API key in URL |
| 901017 | 10 | Credential page or password in URL |
| 901018 | 7 | Email address in URL query |
| 901019 | 8 | Internal document / export URL |
| 901020 | 7 | Cloud storage visit |
| 901021 | 9 | Anonymizer / TOR / VPN site |
| 901022 | 9 | Dangerous file download |
| 901023 | 8 | High-entropy token-like string in URL path |
| **901030** | **12** | risk_score ≥ 9 (composite critical) |

---

## Protection Layers

```
Layer 1 — Endpoint Redaction  ← PRIMARY (most important)
  Browser SQLite → PrivacyEngine → Redacted JSON log
  Raw URL never leaves the endpoint
  Protects 99% of sensitive values before Wazuh ever sees them

Layer 2 — Indexer Pipeline  ← OPTIONAL (safety net)
  wazuh/pipelines/browser_privacy_pipeline.json
  Injected into /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
  Catches anything that slipped past Layer 1 at index time

Layer 3 — Dashboard Access Control  ← RECOMMENDED
  Field-level security in Wazuh Dashboard
  url_hash and title_hash: restricted to SOC lead role
  Normal analysts: see only domain, browser, user, risk_category, url_redacted
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                            ENDPOINT                                 │
│                                                                     │
│  Browser SQLite ──► PrivacyEngine ──► browser_privacy.log (JSON)   │
│  (raw URLs here)    [detect + redact]  [NO tokens, NO passwords]    │
│                                              │                      │
│                            Wazuh Agent ──────┘ (localfile json)     │
└────────────────────────────────────┬────────────────────────────────┘
                                     │
                    ┌────────────────▼─────────────────┐
                    │         WAZUH MANAGER            │
                    │  Decoder → Rules 901000–901030   │
                    │  Filebeat → Wazuh Indexer        │
                    │  (pipeline.json for extra guard) │
                    └────────────────┬─────────────────┘
                                     │
                    ┌────────────────▼─────────────────┐
                    │      WAZUH INDEXER / DASHBOARD   │
                    │  Shows: redacted evidence only   │
                    │  Hides: url_hash, title_hash     │
                    └──────────────────────────────────┘
```

---

## Uninstall

### Linux

```bash
sudo bash installers/linux-installer.sh --uninstall
```

### macOS

```bash
launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-privacy-monitor.plist
rm -rf ~/.browser-privacy-monitor
rm ~/Library/LaunchAgents/com.ramkumar.browser-privacy-monitor.plist
```

### Windows

```powershell
.\install.ps1 -Uninstall
```

---

## Phase Comparison

| Feature | Phase 1 | Phase 2 | Phase 3 |
|---------|:-------:|:-------:|:-------:|
| Multi-browser support | ✅ | ✅ | ✅ |
| Windows / Linux / macOS | ✅ | ✅ | ✅ |
| One-line install | ❌ | ✅ | ✅ |
| Configurable scan interval | ❌ | ✅ | ✅ |
| Interactive interval selector | ❌ | ✅ | ✅ |
| Full URL in log | ✅ | ✅ | ❌ (hashed only) |
| Token / session in log | ✅ | ✅ | ❌ (redacted) |
| Email in log | ✅ | ✅ | ❌ (redacted) |
| risk_score field | ❌ | ❌ | ✅ |
| sensitive_type field | ❌ | ❌ | ✅ |
| url_hash (correlation) | ❌ | ❌ | ✅ |
| Endpoint redaction engine | ❌ | ❌ | ✅ |
| Indexer ingest pipeline | ❌ | ❌ | ✅ (optional) |
| log_format | syslog | syslog | **json** |

---

## Related Projects

| Project | Description |
|---------|-------------|
| [wazuh-browser-history-monitoring](https://github.com/Ramkumar2545/wazuh-browser-history-monitoring) | Phase 1 — Multi-browser history monitoring |
| [browsing-monitoring-history-phases-2](https://github.com/Ramkumar2545/browsing-monitoring-history-phases-2) | Phase 2 — Configurable intervals, full cross-platform |
| [opencti-wazuh-connector-public](https://github.com/Ramkumar2545/opencti-wazuh-connector-public) | OpenCTI ↔ Wazuh threat intelligence connector |

---

## License

MIT — see [LICENSE](LICENSE)

*IT Fortress by Ram Kumar G — Privacy-first security monitoring*
