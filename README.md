# Wazuh Browser Privacy Monitor — Phase 3

> **Privacy-safe browser telemetry for Wazuh SIEM**
> Detect sensitive browsing activity. Never expose the sensitive value itself.

**Author:** Ram Kumar G · (https://github.com/Ramkumar2545)
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

> If using `log_format=json` (default, recommended), this decoder is only needed as a syslog-relay fallback. Wazuh auto-parses JSON fields natively, and rules match on `<decoded_as>json</decoded_as>` + `<field name="integration">browser-privacy-monitor</field>`.
>
> **v2.0.0 note** — If you pulled a pre-v2.0.0 copy and saw no alerts in `alerts.json` (e.g. `tail -f /var/ossec/logs/alerts/alerts.json | grep browser-privacy` returned nothing), that was caused by rules using `<decoded_as>browser-privacy-monitor</decoded_as>`, which never fires for `log_format=json` localfiles. Pull the latest `wazuh/rules/0320-browser_privacy_rules.xml` and restart the manager.

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

### Step 5 — Verify alerts are reaching the manager

Once rules are deployed and the agent is shipping events, watch `alerts.json` live:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i browser-privacy
```

You should see JSON alerts streaming in as endpoints browse. Each line is a full Wazuh alert with `rule.id`, `rule.level`, `rule.groups`, and the decoded fields under `data.*` (e.g. `data.integration`, `data.domain`, `data.risk_category`, `data.url_redacted`).

For pretty-printed output:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json \
  | grep --line-buffered -i browser-privacy \
  | jq 'select(.data.integration == "browser-privacy-monitor") | {ts: .timestamp, rule: .rule.id, level: .rule.level, desc: .rule.description, domain: .data.domain, risk: .data.risk_category}'
```

Other useful live views:

```bash
# Show the raw archive (everything, even level-0 non-alerts)
# Requires <logall_json>yes</logall_json> in ossec.conf <global>
sudo tail -f /var/ossec/logs/archives/archives.json | grep -i browser-privacy

# Only high-severity browser-privacy alerts (level >= 10)
sudo tail -f /var/ossec/logs/alerts/alerts.json \
  | jq --unbuffered 'select(.data.integration == "browser-privacy-monitor" and .rule.level >= 10)'

# Count events per risk_category over the last 1000 alerts
sudo tail -n 1000 /var/ossec/logs/alerts/alerts.json \
  | jq -r 'select(.data.integration == "browser-privacy-monitor") | .data.risk_category' \
  | sort | uniq -c | sort -rn
```

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

#### Step 5 — Restart All Services After Setup

> Once `Loaded Ingest pipelines` is confirmed, restart all Wazuh services in order
> to apply every change end-to-end.

**Make sure you restart in this order — do not skip any service:**

```bash
# 1. Reload systemd unit files (picks up any service file changes)
systemctl daemon-reload

# 2. Restart Wazuh Manager (rules, decoders, ossec.conf changes)
systemctl restart wazuh-manager

# 3. Restart Wazuh Indexer (OpenSearch — pipeline registration takes effect)
systemctl restart wazuh-indexer

# 4. Restart Wazuh Dashboard (UI refresh)
systemctl restart wazuh-dashboard

# 5. Restart Filebeat (re-reads pipeline config, reconnects to Indexer)
systemctl restart filebeat
```

**Verify all services came back up cleanly:**

```bash
systemctl status wazuh-manager   | grep -E "Active|running"
systemctl status wazuh-indexer   | grep -E "Active|running"
systemctl status wazuh-dashboard | grep -E "Active|running"
systemctl status filebeat         | grep -E "Active|running"
```

All four should show `Active: active (running)` before proceeding.

> ⚠️ If `wazuh-indexer` takes more than 30 seconds to start, wait and check again — OpenSearch can be slow on first restart after pipeline changes.

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

#### Step 2 — Register the Pipeline on the Wazuh Indexer

> Push the clean pipeline JSON to your Wazuh Indexer via the OpenSearch REST API.

**Make sure you use your correct:**
- **Username** — `admin`
- **Password** — `Wazuh*12345`
- **IP address** — your Wazuh Indexer IP (use `127.0.0.1` if running on the same node)

> ⚠️ **If the IP address doesn't work**, try `localhost` or `127.0.0.1` instead.

```bash
# Option 1 — Using IP address (replace with your Wazuh Indexer IP)
curl -u admin:Wazuh*12345 -k \
  -X PUT "https://127.0.0.1:9200/_ingest/pipeline/browser-privacy-monitor" \
  -H "Content-Type: application/json" \
  -d @/tmp/browser_privacy_pipeline_clean.json

# Option 2 — If Option 1 fails, try with localhost
curl -u admin:Wazuh*12345 -k \
  -X PUT "https://localhost:9200/_ingest/pipeline/browser-privacy-monitor" \
  -H "Content-Type: application/json" \
  -d @/tmp/browser_privacy_pipeline_clean.json
```

Expected response: `{"acknowledged": true}`

---

#### Step 3 — Verify the Pipeline Was Registered

> Confirm the pipeline exists on the Indexer and all processors are present.

**Make sure you use your correct:**
- **Username** — `admin`
- **Password** — `Wazuh*12345`
- **IP address** — same as Step 2

> ⚠️ **If the IP address doesn't work**, try `localhost` or `127.0.0.1` instead.

```bash
# Option 1 — Using IP address
curl -u admin:Wazuh*12345 -k \
  -X GET "https://127.0.0.1:9200/_ingest/pipeline/browser-privacy-monitor" \
  | python3 -m json.tool

# Option 2 — If Option 1 fails, try with localhost
curl -u admin:Wazuh*12345 -k \
  -X GET "https://localhost:9200/_ingest/pipeline/browser-privacy-monitor" \
  | python3 -m json.tool
```

Expected: JSON output listing all 7 processors (`gsub`, `script`, two `remove`, two `convert`, `set`).

---

#### Step 4 — Test the Pipeline with the Simulate API

> Dry-run the pipeline against a sample browser privacy event without indexing it.
> Confirms redaction, type conversion, and masking all work correctly.

**Make sure you use your correct:**
- **Username** — `admin`
- **Password** — `Wazuh*12345`
- **IP address** — same as Step 2

> ⚠️ **If the IP address doesn't work**, try `localhost` or `127.0.0.1` instead.

```bash
# Option 1 — Using IP address
curl -u admin:Wazuh*12345 -k \
  -X POST "https://127.0.0.1:9200/_ingest/pipeline/browser-privacy-monitor/_simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "docs": [{
      "_source": {
        "data": {
          "url_redacted": "https://portal.company.com/reset?token=eyJhbGciOiJSUz...longtoken...longertoken...",
          "sensitive_detected": "true",
          "risk_score": "10"
        }
      }
    }]
  }'

# Option 2 — If Option 1 fails, try with localhost
curl -u admin:Wazuh*12345 -k \
  -X POST "https://localhost:9200/_ingest/pipeline/browser-privacy-monitor/_simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "docs": [{
      "_source": {
        "data": {
          "url_redacted": "https://portal.company.com/reset?token=eyJhbGciOiJSUz...longtoken...longertoken...",
          "sensitive_detected": "true",
          "risk_score": "10"
        }
      }
    }]
  }'
```

**Expected result after pipeline runs:**

| Field | Input | Output |
|-------|-------|--------|
| `url_redacted` | `...token=eyJhbGci...` | `[PIPELINE-MASKED: high-entropy value detected]` |
| `risk_score` | `"10"` (string) | `10` (integer) |
| `sensitive_detected` | `"true"` (string) | `true` (boolean) |
| `pipeline_processed` | _(absent)_ | `true` |

> **Note on `default_pipeline`:** Applying a `default_pipeline` to `wazuh-alerts-4.x-*` index settings is possible but **not recommended** — it can interfere with Filebeat's existing pipeline and cause indexing failures. Method A (injecting into Filebeat's pipeline) is always safer.

---

### Step 5 — Restart All Services After Setup

> Once the pipeline simulate returns `{"acknowledged": true}` and all steps above are complete,
> restart all Wazuh services to apply every change end-to-end.

**Make sure you restart in this order — do not skip any service:**

```bash
# 1. Reload systemd unit files (picks up any service file changes)
systemctl daemon-reload

# 2. Restart Wazuh Manager (rules, decoders, ossec.conf changes)
systemctl restart wazuh-manager

# 3. Restart Wazuh Indexer (OpenSearch — pipeline registration takes effect)
systemctl restart wazuh-indexer

# 4. Restart Wazuh Dashboard (UI refresh)
systemctl restart wazuh-dashboard

# 5. Restart Filebeat (re-reads pipeline config, reconnects to Indexer)
systemctl restart filebeat
```

**Verify all services came back up cleanly:**

```bash
systemctl status wazuh-manager  | grep -E "Active|running"
systemctl status wazuh-indexer  | grep -E "Active|running"
systemctl status wazuh-dashboard | grep -E "Active|running"
systemctl status filebeat        | grep -E "Active|running"
```

All four should show `Active: active (running)` before proceeding.

> ⚠️ If `wazuh-indexer` takes more than 30 seconds to start, wait and check again — OpenSearch can be slow on first restart after pipeline changes.

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

## Troubleshooting

The commands below cover every failure mode we've seen in production deployments.

### Symptom: `tail -f alerts.json | grep browser-privacy` shows nothing

Work through these in order.

**1. Is the endpoint log growing?**

```bash
# Linux / macOS
tail -f /root/.browser-privacy-monitor/browser_privacy.log
# Windows (on the agent)
Get-Content "C:\BrowserPrivacyMonitor\browser_privacy.log" -Tail 20 -Wait
```

If this is empty, the collector isn't running. Restart the service:

```bash
# Linux
systemctl restart browser-privacy-monitor
# macOS
launchctl kickstart -k gui/$(id -u)/com.itfortress.browser-privacy-monitor
# Windows (as Administrator)
Start-ScheduledTask -TaskName BrowserPrivacyMonitor
```

**2. Is the Wazuh agent reading the file?**

On the agent, confirm the `<localfile>` block is present and `log_format=json`:

```bash
# Linux / macOS
grep -A3 browser-privacy-monitor /var/ossec/etc/ossec.conf   # Linux
grep -A3 browser-privacy-monitor /Library/Ossec/etc/ossec.conf # macOS
```
```powershell
# Windows
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern browser-privacy -Context 0,3
```

Then confirm logcollector is tailing it:

```bash
sudo grep browser_privacy /var/ossec/logs/ossec.log | tail -5
# Expect: "Analyzing file: '/root/.browser-privacy-monitor/browser_privacy.log'."
```

**3. Are events reaching the manager (before rules)?**

Enable the archive log temporarily in `/var/ossec/etc/ossec.conf`:

```xml
<global>
  <logall_json>yes</logall_json>
</global>
```

Then:

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/archives/archives.json | grep -i browser-privacy
```

If events appear here but not in `alerts.json`, the issue is the rules. Continue.

**4. Run `wazuh-logtest` to pinpoint the rule miss**

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste one JSON event from `browser_privacy.log`. Check which rule matches in Phase 3:

| Phase 3 shows … | Meaning | Fix |
|---|---|---|
| `No rule matched` | Decoder ran but your rules didn't load | Confirm `0320-browser_privacy_rules.xml` is in `/var/ossec/etc/rules/` with `chown wazuh:wazuh, chmod 660`, then `systemctl restart wazuh-manager` |
| `id: '86600' Suricata messages` | Suricata rule 86600 intercepted the event | You're on a pre-v2.1.0 rules file. Pull the latest — v2.1.0 uses `<if_sid>86600</if_sid>` to take precedence |
| `id: '901011'` at level 3 | Rules work, but `<log_alert_level>` may be suppressing them | Check `<alerts><log_alert_level>` in `ossec.conf`; lower it to 3 or test with a higher-severity URL |
| Your rule fires at the expected level | Pipeline is healthy | Issue is dashboard-side — see section below |

**5. Is Filebeat shipping alerts to the indexer?**

```bash
sudo filebeat test output
sudo journalctl -u filebeat -n 100 --no-pager | grep -iE "error|warn"
```

**6. Dashboard shows no events even though `alerts.json` has them**

- In Wazuh Dashboard → **Discover** on `wazuh-alerts-*`, filter `data.integration : "browser-privacy-monitor"` and widen the time range to “Last 24 hours”.
- Refresh the index pattern (Stack Management → Index Patterns → `wazuh-alerts-*` → “Refresh field list”) so newly added fields like `data.url_redacted`, `data.risk_score` become searchable.

### Known manager-side errors and their fixes

| Error in `ossec.log` | Cause | Fix |
|---|---|---|
| `ERROR: (1452): Syntax error on regex: '^\{'` | pre-v2.0.0 decoder with `<prematch>{"integration"…</prematch>` | Pull latest repo; the v2.0.0+ decoder file removes that broken prematch |
| `ERROR: (1230): Invalid element in the configuration: 'decoders'` | v2.0.1 wrapped entries in a `<decoders>` root, which analysisd rejects | Pull v2.0.2+ — decoder file has bare `<decoder>` siblings |
| `ERROR: (2107): Decoder configuration error` | Stale custom decoder still referenced | Remove the old decoder block from `/var/ossec/etc/decoders/local_decoder.xml` |
| Phase 3 only fires rule `86600` | Suricata JSON catch-all won the match | Pull v2.1.0+ rules — parent rules now chain via `<if_sid>86600</if_sid>` |

### One-shot health check

After any change to rules or decoders:

```bash
# Offline ruleset syntax check (doesn't require a restart)
sudo /var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK"

# Restart and tail for fresh errors
sudo systemctl restart wazuh-manager
sudo tail -n 40 /var/ossec/logs/ossec.log | grep -iE "error|critical|started"

# Live-watch browser-privacy alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i browser-privacy
```

### Generate a high-severity test alert

From any monitored browser, visit:

- `https://accounts.google.com/signin` → triggers **901024** at level 10 (credential page)
- `https://drive.google.com/` → triggers **901020** at level 7 (cloud storage)
- `https://www.torproject.org/` → triggers **901021** at level 9 (anonymizer)

The event shows up in `alerts.json` within one scan interval (default 5 minutes; set lower in `.browser_privacy_config.json` for testing).

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
