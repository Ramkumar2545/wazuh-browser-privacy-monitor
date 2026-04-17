# ==============================================================================
#  Wazuh Browser Privacy Monitor — Windows Installer
#  Author  : Ram Kumar G (IT Fortress)
#  Version : 1.0.0 (Phase 3 - Privacy-Safe Telemetry Edition)
#
#  Installs:
#    - Collector script  → C:\BrowserPrivacyMonitor\
#    - Config file       → C:\BrowserPrivacyMonitor\.browser_privacy_config.json
#    - Log file          → C:\BrowserPrivacyMonitor\browser_privacy.log
#    - Task Scheduler    → "BrowserPrivacyMonitor" (runs as SYSTEM on boot + every 5m)
#    - Wazuh localfile   → appended to ossec.conf
#
#  Usage (Admin PowerShell):
#    Set-ExecutionPolicy Bypass -Scope Process -Force
#    .\windows-installer.ps1
#    .\windows-installer.ps1 -Interval 300
#    .\windows-installer.ps1 -Uninstall
# ==============================================================================
param(
    [int]$Interval    = 300,
    [switch]$Uninstall
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ── Config ────────────────────────────────────────────────────────────────────
$InstallDir    = "C:\BrowserPrivacyMonitor"
$ScriptName    = "browser-privacy-monitor.py"
$ScriptPath    = "$InstallDir\$ScriptName"
$LogFile       = "$InstallDir\browser_privacy.log"
$ConfigFile    = "$InstallDir\.browser_privacy_config.json"
$TaskName      = "BrowserPrivacyMonitor"
$OssecConf     = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$CollectorUrl  = "https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-privacy-monitor/main/collector/browser-privacy-monitor.py"

function Write-Step  { param($msg) Write-Host "[STEP]  $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── Uninstall path ─────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Step "Uninstalling $TaskName..."
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
    Write-OK "Uninstalled. Log data removed."
    exit 0
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║  Wazuh Browser Privacy Monitor — Windows Installer      ║" -ForegroundColor White
Write-Host "║  Version 1.0.0 (Phase 3 - Privacy-Safe Telemetry)       ║" -ForegroundColor White
Write-Host "║  IT Fortress by Ram Kumar G                              ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host ""

# ── Step 1: Python check ──────────────────────────────────────────────────────
Write-Step "Step 1/6 — Checking Python 3..."
$PythonPath = $null
foreach ($p in @("python", "python3", "py")) {
    try {
        $v = & $p --version 2>&1
        if ($v -match "Python 3") { $PythonPath = (Get-Command $p).Source; break }
    } catch {}
}
if (-not $PythonPath) { Write-Err "Python 3 not found. Download from https://python.org/downloads" }
Write-OK "Python found: $PythonPath"

# ── Step 2: Create directories ────────────────────────────────────────────────
Write-Step "Step 2/6 — Creating install directory..."
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
if (-not (Test-Path $LogFile)) { New-Item -ItemType File -Path $LogFile -Force | Out-Null }
# Lock down permissions — only SYSTEM and Admins
$Acl = Get-Acl $InstallDir
$Acl.SetAccessRuleProtection($true, $false)
$SysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.AddAccessRule($SysRule)
$Acl.AddAccessRule($AdminRule)
Set-Acl $InstallDir $Acl
Write-OK "Directory: $InstallDir (SYSTEM + Admins only)"

# ── Step 3: Download/copy collector ──────────────────────────────────────────
Write-Step "Step 3/6 — Installing collector script..."
$LocalScript = Join-Path (Split-Path $PSScriptRoot -Parent) "collector\$ScriptName"
if (Test-Path $LocalScript) {
    Copy-Item $LocalScript $ScriptPath -Force
    Write-OK "Installed from local copy."
} else {
    try {
        Invoke-WebRequest -Uri $CollectorUrl -OutFile $ScriptPath -UseBasicParsing
        Write-OK "Downloaded from GitHub."
    } catch {
        Write-Err "Cannot download collector: $_"
    }
}

# ── Step 4: Write config (BOM-free UTF-8) ────────────────────────────────────
Write-Step "Step 4/6 — Writing config (interval: ${Interval}s)..."
$ConfigContent = @"
{
  "scan_interval_seconds": $Interval,
  "version": "1.0.0"
}
"@
# Use UTF-8 without BOM (avoids PowerShell 5.x BOM injection)
[System.IO.File]::WriteAllText($ConfigFile, $ConfigContent, [System.Text.UTF8Encoding]::new($false))
Write-OK "Config: $ConfigFile"

# ── Step 5: Task Scheduler ───────────────────────────────────────────────────
Write-Step "Step 5/6 — Creating Scheduled Task..."
# Remove old task if exists
try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$Action  = New-ScheduledTaskAction -Execute $PythonPath -Argument $ScriptPath -WorkingDirectory $InstallDir
$Trigger = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -RepetitionInterval ([TimeSpan]::FromSeconds($Interval)) -Once -At (Get-Date))
)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$Settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
                                           -RestartCount 3 `
                                           -RestartInterval ([TimeSpan]::FromMinutes(1)) `
                                           -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Wazuh Browser Privacy Monitor Phase 3 — Privacy-Safe Telemetry" `
    -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2
$TaskStatus = (Get-ScheduledTask -TaskName $TaskName).State
Write-OK "Task '$TaskName' created. Status: $TaskStatus"

# ── Step 6: Wazuh localfile config ────────────────────────────────────────────
Write-Step "Step 6/6 — Configuring Wazuh agent localfile..."
$LocalfileBlock = @"

  <!-- Browser Privacy Monitor Phase 3 - Privacy-Safe Telemetry -->
  <localfile>
    <log_format>json</log_format>
    <location>C:\BrowserPrivacyMonitor\browser_privacy.log</location>
    <label key="integration">browser-privacy-monitor</label>
  </localfile>
"@

if (Test-Path $OssecConf) {
    $Content = Get-Content $OssecConf -Raw
    if ($Content -match "browser-privacy-monitor") {
        Write-Warn "Wazuh localfile already configured. Skipping."
    } else {
        $Content = $Content -replace "</ossec_config>", "$LocalfileBlock`n</ossec_config>"
        [System.IO.File]::WriteAllText($OssecConf, $Content, [System.Text.UTF8Encoding]::new($false))
        Write-OK "Added localfile to: $OssecConf"
        # Restart Wazuh agent service
        try {
            Restart-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
            Write-OK "Wazuh agent restarted."
        } catch {
            Write-Warn "Could not restart Wazuh agent. Restart manually."
        }
    }
} else {
    Write-Warn "Wazuh ossec.conf not found at: $OssecConf"
    Write-Warn "Add this block manually:"
    Write-Host $LocalfileBlock -ForegroundColor Yellow
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green -NoNewline
Write-Host ""
Write-Host "  Log file:   $LogFile"
Write-Host "  Config:     $ConfigFile"
Write-Host "  Task:       Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Live tail:  Get-Content '$LogFile' -Tail 20 -Wait"
Write-Host "  Uninstall:  .\windows-installer.ps1 -Uninstall"
Write-Host ""
Write-Host "Design: collect raw locally → detect locally → send only REDACTED to Wazuh" -ForegroundColor Cyan
Write-Host ""
