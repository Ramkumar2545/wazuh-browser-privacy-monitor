<#
.SYNOPSIS
    Wazuh Browser Privacy Monitor Phase 3 - Windows One-Line Installer
    Author  : Ram Kumar G (IT Fortress)
    Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)

.DESCRIPTION
    Downloads the Phase 3 privacy-safe collector from GitHub and installs it.
    Prompts for scan interval during installation.
    Registers a Scheduled Task (AtLogon + Repeat) running as SYSTEM.
    Updates Wazuh ossec.conf automatically with log_format=json.

    DESIGN PRINCIPLE:
      Raw URLs, tokens, session IDs, API keys are NEVER written to log.
      Wazuh only receives redacted JSON — no raw secrets reach the dashboard.

    REQUIREMENTS:
      1. Run as Administrator.
      2. Python 3.8+ installed System-Wide (Install for All Users + Add to PATH).

.ONE-LINE INSTALL (interactive, prompts for interval):
    powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.ps1' | iex"

.ONE-LINE INSTALL (non-interactive, pick interval via env var):
    powershell -ExecutionPolicy Bypass -Command "$env:BPM_INTERVAL='30m'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/install.ps1' | iex"

.FROM DOWNLOADED FILE (supports param):
    .\install.ps1 -Interval 30m
    .\install.ps1 -Interval 300
    .\install.ps1 -Interval 5           # menu number
    .\install.ps1 -NonInteractive       # accept default 30m

.UNINSTALL:
    powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
#>

param(
    [string]$Interval = "",
    [switch]$NonInteractive,
    [switch]$Uninstall
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$REPO_RAW    = "https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main"
$InstallDir  = "C:\BrowserPrivacyMonitor"
$ScriptName  = "browser-privacy-monitor.py"
$ConfigName  = ".browser_privacy_config.json"
$TaskName    = "BrowserPrivacyMonitor"
$LogFile     = "$InstallDir\browser_privacy.log"
$WazuhConf   = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WazuhSvc    = "WazuhSvc"
$DestScript  = "$InstallDir\$ScriptName"
$DestConfig  = "$InstallDir\$ConfigName"
$Marker      = "<!-- BROWSER_PRIVACY_MONITOR_P3 -->"

# BOM-free UTF-8 writer — PowerShell 5.x Set-Content -Encoding UTF8 writes BOM which breaks Python json.load()
$Utf8NoBom   = New-Object System.Text.UTF8Encoding $false

# ── Uninstall ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Host "[UNINSTALL] Removing $TaskName..." -ForegroundColor Yellow
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    $Startup  = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\WazuhBrowserPrivacyMonitor.lnk"
    if (Test-Path $Startup) { Remove-Item $Startup -Force }
    if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
    Write-Host "[OK] Uninstalled successfully." -ForegroundColor Green
    exit 0
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Wazuh Browser Privacy Monitor Phase 3 - Windows Installer       ║" -ForegroundColor Cyan
Write-Host "║  Version 1.0.0 | Privacy-Safe Telemetry | IT Fortress            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Design: Raw URLs stay on endpoint — Wazuh only receives redacted JSON" -ForegroundColor Cyan
Write-Host ""

# ── Admin check ───────────────────────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] ERROR: Run this script as Administrator." -ForegroundColor Red
    exit 1
}

# ── STEP 1: Python detection ──────────────────────────────────────────────────
Write-Host "[1] Detecting Python (System-Wide)..." -ForegroundColor Yellow
$PythonExe = $null
$CommonPaths = @(
    "C:\Program Files\Python314\python.exe",
    "C:\Program Files\Python313\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python310\python.exe",
    "C:\Program Files\Python39\python.exe",
    "C:\Program Files\Python38\python.exe",
    "C:\Program Files (x86)\Python314\python.exe",
    "C:\Program Files (x86)\Python313\python.exe",
    "C:\Program Files (x86)\Python312\python.exe",
    "C:\Python314\python.exe",
    "C:\Python313\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe"
)
foreach ($p in $CommonPaths) {
    if (Test-Path $p) { $PythonExe = $p; Write-Host "    [+] Found: $p" -ForegroundColor Green; break }
}
if (-not $PythonExe) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*\Users\*") {
        $PythonExe = $cmd.Source
        Write-Host "    [+] Found via PATH: $PythonExe" -ForegroundColor Green
    }
}
if (-not $PythonExe) {
    Write-Host "[-] Python not found. Install Python 3.x from https://python.org" -ForegroundColor Red
    Write-Host "    Select: Install for All Users + Add to PATH" -ForegroundColor Yellow
    exit 1
}
$PyDir       = Split-Path $PythonExe -Parent
$PythonWExe  = Join-Path $PyDir "pythonw.exe"
if (-not (Test-Path $PythonWExe)) { $PythonWExe = $PythonExe }
Write-Host "    [+] Windowless Python: $PythonWExe" -ForegroundColor Green

# ── STEP 2: Interval selection ────────────────────────────────────────────────
# Priority: -Interval param → $env:BPM_INTERVAL → -NonInteractive / $env:BPM_NONINTERACTIVE → prompt
$IntervalMap = @{
    "1"  = @{ Secs = 60;    Label = "1m";  Mins = 1    }
    "2"  = @{ Secs = 300;   Label = "5m";  Mins = 5    }
    "3"  = @{ Secs = 600;   Label = "10m"; Mins = 10   }
    "4"  = @{ Secs = 1200;  Label = "20m"; Mins = 20   }
    "5"  = @{ Secs = 1800;  Label = "30m"; Mins = 30   }
    "6"  = @{ Secs = 3600;  Label = "60m"; Mins = 60   }
    "7"  = @{ Secs = 7200;  Label = "2h";  Mins = 120  }
    "8"  = @{ Secs = 21600; Label = "6h";  Mins = 360  }
    "9"  = @{ Secs = 43200; Label = "12h"; Mins = 720  }
    "10" = @{ Secs = 86400; Label = "24h"; Mins = 1440 }
}

function Resolve-Interval {
    param([string]$v)
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    $v = $v.Trim().ToLower()
    if ($IntervalMap.ContainsKey($v)) {
        return @{ Secs = $IntervalMap[$v].Secs; Label = $IntervalMap[$v].Label; Mins = $IntervalMap[$v].Mins }
    }
    $secs = $null
    if     ($v -match '^([0-9]+)m$') { $secs = [int]$Matches[1] * 60 }
    elseif ($v -match '^([0-9]+)h$') { $secs = [int]$Matches[1] * 3600 }
    elseif ($v -match '^([0-9]+)d$') { $secs = [int]$Matches[1] * 86400 }
    elseif ($v -match '^([0-9]+)s?$') { $secs = [int]$Matches[1] }
    else { return $null }
    if ($secs -lt 60)    { $secs = 60 }
    if ($secs -gt 86400) { $secs = 86400 }
    $mins = [Math]::Max(1, [int]($secs / 60))
    # Prefer short label when it maps cleanly
    $label = switch ($secs) {
        60    { "1m" }
        300   { "5m" }
        600   { "10m" }
        1200  { "20m" }
        1800  { "30m" }
        3600  { "60m" }
        7200  { "2h" }
        21600 { "6h" }
        43200 { "12h" }
        86400 { "24h" }
        default { "${secs}s" }
    }
    return @{ Secs = $secs; Label = $label; Mins = $mins }
}

$resolved = $null
if (-not [string]::IsNullOrWhiteSpace($Interval))           { $resolved = Resolve-Interval $Interval }
if (-not $resolved -and $env:BPM_INTERVAL)                  { $resolved = Resolve-Interval $env:BPM_INTERVAL }
$forceNonInteractive = $NonInteractive.IsPresent -or ($env:BPM_NONINTERACTIVE -eq "1")

if ($resolved) {
    $SECS = $resolved.Secs; $LABEL = $resolved.Label; $MINS = $resolved.Mins
    Write-Host ""
    Write-Host "[2] Using interval from flag/env: $LABEL ($SECS seconds)" -ForegroundColor Green
} elseif ($forceNonInteractive) {
    $SECS = 1800; $LABEL = "30m"; $MINS = 30
    Write-Host ""
    Write-Host "[2] Non-interactive mode: default $LABEL (1800 seconds)" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[2] Select scan interval (how often to check browser history):" -ForegroundColor Yellow
    Write-Host "     1)  1  minute   (high I/O — testing only)" -ForegroundColor Gray
    Write-Host "     2)  5  minutes" -ForegroundColor Gray
    Write-Host "     3)  10 minutes" -ForegroundColor Gray
    Write-Host "     4)  20 minutes" -ForegroundColor Gray
    Write-Host "     5)  30 minutes  (recommended)" -ForegroundColor Cyan
    Write-Host "     6)  60 minutes / 1 hour" -ForegroundColor Gray
    Write-Host "     7)  2  hours" -ForegroundColor Gray
    Write-Host "     8)  6  hours" -ForegroundColor Gray
    Write-Host "     9)  12 hours" -ForegroundColor Gray
    Write-Host "    10)  24 hours    (once per day)" -ForegroundColor Gray
    Write-Host ""
    # Read-Host reads from the console host, so it works even through 'iwr | iex'
    $choice = Read-Host "    Enter choice [1-10] (default: 5 = 30 minutes)"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "5" }
    if (-not $IntervalMap.ContainsKey($choice)) { $choice = "5" }
    $SECS  = $IntervalMap[$choice].Secs
    $LABEL = $IntervalMap[$choice].Label
    $MINS  = $IntervalMap[$choice].Mins
    Write-Host "    [+] Selected: $LABEL ($SECS seconds)" -ForegroundColor Green
}
$RepeatMins = if ($MINS -ge 1440) { "1440" } else { "$MINS" }

# ── STEP 3: Create install directory ─────────────────────────────────────────
Write-Host ""
Write-Host "[3] Creating $InstallDir..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }
# Restrict to SYSTEM + Administrators only
$Acl = Get-Acl $InstallDir
$Acl.SetAccessRuleProtection($true, $false)
$SysRule   = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.AddAccessRule($SysRule)
$Acl.AddAccessRule($AdminRule)
Set-Acl $InstallDir $Acl
Write-Host "    [+] Directory created: $InstallDir (SYSTEM + Admins only)" -ForegroundColor Green

# ── STEP 4: Kill any existing process ────────────────────────────────────────
Write-Host ""
Write-Host "[4] Stopping any existing collector process..." -ForegroundColor Yellow
$killed = $false
Get-Process -Name python*, pythonw* -ErrorAction SilentlyContinue | ForEach-Object {
    $cmdline = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
    if ($cmdline -like "*browser-privacy-monitor*") {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Host "    [+] Killed old collector PID $($_.Id)" -ForegroundColor Green
        $killed = $true
    }
}
if (-not $killed) { Write-Host "    [=] No existing collector process found" -ForegroundColor Gray }
Start-Sleep -Seconds 1

# ── STEP 5: Download collector ────────────────────────────────────────────────
Write-Host ""
Write-Host "[5] Downloading Phase 3 privacy-safe collector..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -UseBasicParsing "$REPO_RAW/collector/browser-privacy-monitor.py" -OutFile $DestScript
    Write-Host "    [+] Downloaded: $DestScript" -ForegroundColor Green
} catch {
    Write-Host "[-] Download failed: $_" -ForegroundColor Red; exit 1
}

# ── STEP 6: Write config (BOM-free UTF-8) ────────────────────────────────────
Write-Host ""
Write-Host "[6] Writing interval config (BOM-free UTF-8)..." -ForegroundColor Yellow
$ConfigJson = "{`"scan_interval_seconds`": $SECS, `"scan_interval_label`": `"$LABEL`", `"version`": `"1.0.0`"}"
[System.IO.File]::WriteAllText($DestConfig, $ConfigJson, $Utf8NoBom)
Write-Host "    [+] Config: $DestConfig  [$LABEL = $SECS s]" -ForegroundColor Green

# ── STEP 7: Scheduled Task (AtLogon + Repeat) ────────────────────────────────
Write-Host ""
Write-Host "[7] Creating Scheduled Task: $TaskName (SYSTEM, AtLogon + Repeat every $RepeatMins min)..." -ForegroundColor Yellow

$Action    = New-ScheduledTaskAction -Execute $PythonWExe -Argument "`"$DestScript`"" -WorkingDirectory $InstallDir
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$Settings  = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartInterval (New-TimeSpan -Minutes ([Math]::Max(1, $MINS))) `
    -RestartCount 9999 `
    -MultipleInstances IgnoreNew

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal | Out-Null
Set-ScheduledTask   -TaskName $TaskName -Settings $Settings | Out-Null

# Inject RepetitionInterval into task XML for native repeat (most reliable method)
$TaskXml   = (Export-ScheduledTask -TaskName $TaskName)
$RepeatPT  = "PT${RepeatMins}M"
$TaskXml   = $TaskXml -replace "(<Triggers>.*?<Boot>.*?</Boot>)(.*?</Triggers>)",
    "<Triggers><BootTrigger><Repetition><Interval>$RepeatPT</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></BootTrigger></Triggers>"
$TaskXml | Register-ScheduledTask -TaskName $TaskName -Force | Out-Null

Write-Host "    [+] Task registered: AtStartup + repeat every $RepeatMins min as SYSTEM" -ForegroundColor Green

# ── STEP 8: Startup shortcut failsafe ────────────────────────────────────────
Write-Host ""
Write-Host "[8] Creating startup shortcut (failsafe)..." -ForegroundColor Yellow
$StartupDir   = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$ShortcutPath = Join-Path $StartupDir "WazuhBrowserPrivacyMonitor.lnk"
$WShell = New-Object -ComObject WScript.Shell
$SC = $WShell.CreateShortcut($ShortcutPath)
$SC.TargetPath       = $PythonWExe
$SC.Arguments        = "`"$DestScript`""
$SC.WorkingDirectory = $InstallDir
$SC.Save()
Write-Host "    [+] Shortcut: $ShortcutPath" -ForegroundColor Green

# ── STEP 9: Wazuh ossec.conf (log_format=json, BOM-free) ─────────────────────
Write-Host ""
Write-Host "[9] Configuring Wazuh ossec.conf (log_format=json)..." -ForegroundColor Yellow
if (Test-Path $WazuhConf) {
    $Content = Get-Content $WazuhConf -Raw
    if ($Content -match [regex]::Escape($Marker)) {
        Write-Host "    [=] localfile block already present — skipping" -ForegroundColor Gray
    } else {
        $Block = "`n  $Marker`n  <localfile>`n    <log_format>json</log_format>`n    <location>$LogFile</location>`n    <label key=`"integration`">browser-privacy-monitor</label>`n  </localfile>"
        $Content = $Content -replace "</ossec_config>", "$Block`n</ossec_config>"
        [System.IO.File]::WriteAllText($WazuhConf, $Content, $Utf8NoBom)
        Write-Host "    [+] localfile block added (log_format=json)" -ForegroundColor Green
        try {
            Restart-Service -Name $WazuhSvc -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            $svc = Get-Service $WazuhSvc -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Write-Host "    [+] Wazuh agent: Running" -ForegroundColor Green
            } else {
                Write-Host "    [!] Restart Wazuh agent manually" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    [!] Could not restart Wazuh agent: $_" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "    [!] ossec.conf not found at: $WazuhConf" -ForegroundColor Yellow
    Write-Host "    Add this block manually inside <ossec_config>:"
    Write-Host "      $Marker"
    Write-Host "      <localfile>"
    Write-Host "        <log_format>json</log_format>"
    Write-Host "        <location>$LogFile</location>"
    Write-Host "        <label key=""integration"">browser-privacy-monitor</label>"
    Write-Host "      </localfile>"
}

# ── STEP 10: Start now ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[10] Starting collector now..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$taskState = (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State
Write-Host "    [+] Task state: $taskState" -ForegroundColor Green

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  [SUCCESS] Phase 3 Installation Complete!                        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Interval  : $LABEL ($SECS seconds)"
Write-Host "  Log file  : $LogFile  [JSON — NO raw URLs, NO tokens]"
Write-Host "  Watch     : Get-Content '$LogFile' -Tail 20 -Wait" -ForegroundColor Cyan
Write-Host "  Task      : Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host "  Uninstall : .\install.ps1 -Uninstall" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Wazuh Manager next steps:" -ForegroundColor Cyan
Write-Host "    1. Copy  wazuh\rules\0320-browser_privacy_rules.xml     → \var\ossec\etc\rules\"
Write-Host "    2. Copy  wazuh\decoders\0320-browser_privacy_decoder.xml → \var\ossec\etc\decoders\"
Write-Host "    3. Run   wazuh-logtest -V && systemctl restart wazuh-manager"
Write-Host ""
Write-Host "  Design: collect raw locally → detect locally → send ONLY redacted JSON to Wazuh" -ForegroundColor Cyan
Write-Host ""
