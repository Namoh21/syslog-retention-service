#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Full setup menu for the Syslog Retention and SIEM Service.
    Run this script once to install, or again to repair/upgrade.

.DESCRIPTION
    Menu-driven installer that lets you:
      1) Fresh install
      2) Update (git pull + pip + service restart)
      3) Uninstall
      4) Open web console
      5) View service status / logs
      6) Edit .env configuration
      7) Exit

.NOTES
    Requires: Python 3.10+, Git, internet access (first run only for NSSM).
    Run as Administrator from the syslog_service directory.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$ServiceName  = "SyslogRetentionSvc"
$DisplayName  = "Syslog Retention and SIEM Service"
$ScriptDir    = $PSScriptRoot
$VenvDir      = Join-Path $ScriptDir ".venv"
$PythonExe    = Join-Path $VenvDir "Scripts\python.exe"
$PipExe       = Join-Path $VenvDir "Scripts\pip.exe"
$MainScript   = Join-Path $ScriptDir "main.py"
$NssmDir      = Join-Path $ScriptDir "tools\nssm"
$NssmExe      = Join-Path $NssmDir "win64\nssm.exe"
$LogDir       = Join-Path $ScriptDir "logs"
$DataDir      = Join-Path $ScriptDir "data"
$EnvFile      = Join-Path $ScriptDir ".env"
$ReqFile      = Join-Path $ScriptDir "requirements.txt"
$SyslogPort   = 514
$WebPort      = 8080
$NssmUrl      = "https://nssm.cc/release/nssm-2.24.zip"

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |   Syslog Retention and SIEM Service  v1.1        |" -ForegroundColor Cyan
    Write-Host "  |   Setup / Management Console                     |" -ForegroundColor Cyan
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($msg)  { Write-Host "  >> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "     OK: $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "     WARN: $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "     ERROR: $msg" -ForegroundColor Red }
function Wait-Enter        { Write-Host ""; Read-Host "  Press Enter to continue" | Out-Null }

function Get-ServiceStatus {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return "Not installed" }
    return $svc.Status
}

function Get-PythonPath {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command python3 -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Install-Nssm {
    if (Test-Path $NssmExe) { return }
    Write-Step "Downloading NSSM service wrapper..."
    $zipPath = Join-Path $ScriptDir "tools\_nssm.zip"
    New-Item -ItemType Directory -Force -Path (Join-Path $ScriptDir "tools") | Out-Null
    try {
        Invoke-WebRequest -Uri $NssmUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath (Join-Path $ScriptDir "tools") -Force
        $extracted = Get-ChildItem (Join-Path $ScriptDir "tools") -Filter "nssm*" -Directory | Select-Object -First 1
        if ($extracted -and $extracted.FullName -ne $NssmDir) {
            if (Test-Path $NssmDir) { Remove-Item $NssmDir -Recurse -Force }
            Rename-Item $extracted.FullName $NssmDir
        }
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-Ok "NSSM installed"
    } catch {
        Write-Err "Failed to download NSSM: $_"
        Write-Warn "Download manually from https://nssm.cc and extract to tools\nssm\"
        Wait-Enter
        throw
    }
}

function Read-EnvInput {
    param([string]$Prompt, [string]$Default = "", [bool]$Secret = $false)
    $display = if ($Default -ne "") { "$Prompt [$Default]" } else { $Prompt }
    Write-Host "  $display" -ForegroundColor White -NoNewline
    Write-Host " : " -NoNewline
    if ($Secret) {
        $val = Read-Host -AsSecureString
        $val = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                   [Runtime.InteropServices.Marshal]::SecureStringToBSTR($val))
    } else {
        $val = Read-Host
    }
    if ($val -eq "" -and $Default -ne "") { return $Default }
    return $val
}

function Initialize-EnvFile {
    if (Test-Path $EnvFile) {
        Write-Ok ".env already exists - skipping configuration wizard"
        Write-Host "  (Select option 6 from the main menu to edit it)" -ForegroundColor Gray
        return
    }

    Write-Host ""
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |   Configuration Wizard                           |" -ForegroundColor Yellow
    Write-Host "  |   Press Enter to accept the [default value]      |" -ForegroundColor Yellow
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""

    # Secret key - auto-generate, no need to ask
    $secret = [System.BitConverter]::ToString(
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    ).Replace("-","").ToLower()
    Write-Ok "SECRET_KEY auto-generated"

    # Admin credentials
    Write-Host ""
    Write-Host "  -- Admin Account --" -ForegroundColor Cyan
    $adminUser = Read-EnvInput "Admin username" "admin"
    do {
        $adminPass = Read-EnvInput "Admin password (min 8 chars)" "" $true
        if ($adminPass.Length -lt 8) { Write-Warn "Password must be at least 8 characters." }
    } while ($adminPass.Length -lt 8)

    # Anthropic API key
    Write-Host ""
    Write-Host "  -- Claude AI --" -ForegroundColor Cyan
    Write-Host "  Your Anthropic API key is needed for AI log analysis." -ForegroundColor Gray
    Write-Host "  Get one at: https://console.anthropic.com" -ForegroundColor Gray
    Write-Host "  (Leave blank to skip - you can add it later in .env)" -ForegroundColor Gray
    $anthropicKey = Read-EnvInput "Anthropic API key" ""

    $claudeModels = @("claude-sonnet-4-6", "claude-opus-4-7", "claude-haiku-4-5-20251001")
    Write-Host ""
    Write-Host "  Claude model options:" -ForegroundColor Gray
    for ($i = 0; $i -lt $claudeModels.Length; $i++) {
        $label = if ($i -eq 0) { " (recommended)" } else { "" }
        Write-Host "    $($i+1). $($claudeModels[$i])$label" -ForegroundColor Gray
    }
    $modelChoice = Read-EnvInput "Choose model 1-3" "1"
    $idx = [int]$modelChoice - 1
    if ($idx -lt 0 -or $idx -ge $claudeModels.Length) { $idx = 0 }
    $claudeModel = $claudeModels[$idx]

    # Syslog ports
    Write-Host ""
    Write-Host "  -- Syslog Ports --" -ForegroundColor Cyan
    Write-Host "  Port 514 requires Administrator. Use 5514 if you have issues." -ForegroundColor Gray
    $udpPort = Read-EnvInput "Syslog UDP port" "514"
    $tcpPort = Read-EnvInput "Syslog TCP port" "514"

    # Web console
    Write-Host ""
    Write-Host "  -- Web Console --" -ForegroundColor Cyan
    $apiPort = Read-EnvInput "Web console port" "8080"
    $apiHost = Read-EnvInput "Bind address (0.0.0.0 = all interfaces)" "0.0.0.0"

    # Retention
    Write-Host ""
    Write-Host "  -- Log Retention --" -ForegroundColor Cyan
    $retDays = Read-EnvInput "Retention period in days" "90"
    $maxEntries = Read-EnvInput "Maximum log entries" "5000000"

    # External API keys
    Write-Host ""
    Write-Host "  -- External API Keys (optional) --" -ForegroundColor Cyan
    Write-Host "  Pre-shared keys for Claude Projects or scripts (comma-separated)." -ForegroundColor Gray
    Write-Host "  Leave blank - you can generate keys in the web console later." -ForegroundColor Gray
    $extKeys = Read-EnvInput "External API keys" ""

    # Write .env
    $envContent = @"
# Generated by Setup.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

SECRET_KEY=$secret
ADMIN_USERNAME=$adminUser
ADMIN_PASSWORD=$adminPass

ANTHROPIC_API_KEY=$anthropicKey
CLAUDE_MODEL=$claudeModel

SYSLOG_UDP_PORT=$udpPort
SYSLOG_TCP_PORT=$tcpPort

API_HOST=$apiHost
API_PORT=$apiPort

RETENTION_DAYS=$retDays
MAX_LOG_ENTRIES=$maxEntries

EXTERNAL_API_KEYS=$extKeys
"@
    Set-Content $EnvFile $envContent -Encoding UTF8
    Write-Host ""
    Write-Ok ".env saved to $EnvFile"
}

function Set-FirewallRules {
    $profiles = "Private", "Domain"
    New-NetFirewallRule -DisplayName "Syslog UDP $SyslogPort" -Direction Inbound -Protocol UDP -LocalPort $SyslogPort -Action Allow -Profile $profiles -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Syslog TCP $SyslogPort" -Direction Inbound -Protocol TCP -LocalPort $SyslogPort -Action Allow -Profile $profiles -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "SIEM Web Console $WebPort" -Direction Inbound -Protocol TCP -LocalPort $WebPort  -Action Allow -Profile $profiles -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "Firewall rules set (Private + Domain profiles)"
}

function Start-Install {
    Write-Banner
    Write-Host "  [ INSTALL / REPAIR ]" -ForegroundColor Green
    Write-Host ""

    Write-Step "Checking Python 3.10+"
    $pyPath = Get-PythonPath
    if (-not $pyPath) {
        Write-Err "Python not found in PATH."
        Write-Host "  Install Python 3.10+ from https://python.org (check 'Add to PATH')."
        Wait-Enter
        return
    }
    $pyVer = & $pyPath -c "import sys; print(str(sys.version_info.major) + '.' + str(sys.version_info.minor))" 2>$null
    Write-Ok "Python $pyVer at $pyPath"

    Write-Step "Checking Git"
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) {
        Write-Warn "Git not found - update feature will be unavailable."
    } else {
        Write-Ok "Git at $($gitCmd.Source)"
    }

    Write-Step "Configuring .env"
    Initialize-EnvFile

    Write-Step "Creating Python virtual environment"
    if (-not (Test-Path $VenvDir)) {
        & $pyPath -m venv $VenvDir
        Write-Ok "Venv created"
    } else {
        Write-Ok "Venv already exists"
    }

    Write-Step "Installing Python dependencies (this may take a minute)..."
    & $PipExe install --upgrade pip --quiet
    & $PipExe install -r $ReqFile --quiet
    Write-Ok "Dependencies installed"

    New-Item -ItemType Directory -Force -Path $LogDir  | Out-Null
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

    Install-Nssm

    Write-Step "Registering Windows service"
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Service already registered - reconfiguring"
        & $NssmExe stop   $ServiceName confirm 2>$null
        & $NssmExe remove $ServiceName confirm 2>$null
    }
    & $NssmExe install $ServiceName $PythonExe
    & $NssmExe set     $ServiceName AppParameters  $MainScript
    & $NssmExe set     $ServiceName AppDirectory   $ScriptDir
    & $NssmExe set     $ServiceName DisplayName    $DisplayName
    & $NssmExe set     $ServiceName Description    "Syslog receiver and SIEM for Unifi Dream Machine. Web console on port $WebPort."
    & $NssmExe set     $ServiceName Start          SERVICE_AUTO_START
    & $NssmExe set     $ServiceName AppStdout      (Join-Path $LogDir "service.log")
    & $NssmExe set     $ServiceName AppStderr      (Join-Path $LogDir "service_err.log")
    & $NssmExe set     $ServiceName AppRotateFiles 1
    & $NssmExe set     $ServiceName AppRotateBytes 10485760
    Write-Ok "Service registered"

    Write-Step "Configuring Windows Firewall"
    Set-FirewallRules

    Write-Step "Starting service"
    & $NssmExe start $ServiceName
    Start-Sleep -Seconds 3
    $svcStatus = Get-ServiceStatus
    Write-Ok "Service status: $svcStatus"

    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host "  Installation complete!" -ForegroundColor Green
    Write-Host "  Web console : http://localhost:$WebPort" -ForegroundColor Green
    Write-Host "  Syslog      : UDP/TCP port $SyslogPort" -ForegroundColor Green
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Point your UDM syslog to this PC on port $SyslogPort"
    Write-Host "  2. Open http://localhost:$WebPort and change the admin password"
    Write-Host "  3. Add ANTHROPIC_API_KEY to .env for AI analysis"
    Write-Host "  4. Generate an API key in the web GUI for Claude Projects"
    Wait-Enter
}

function Start-Update {
    Write-Banner
    Write-Host "  [ UPDATE ]" -ForegroundColor Cyan
    Write-Host ""

    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) {
        Write-Err "Git is not installed. Cannot auto-update."
        Write-Warn "Download the latest release manually from GitHub."
        Wait-Enter
        return
    }

    Write-Step "Pulling latest code from GitHub"
    Push-Location $ScriptDir
    try {
        $dirty = git status --porcelain 2>$null
        if ($dirty) {
            git stash push -m "auto-stash $(Get-Date -Format 'yyyyMMdd-HHmmss')" 2>$null
            Write-Warn "Local changes stashed"
        }
        git fetch origin 2>$null
        git pull origin main 2>$null
        Write-Ok "Code updated"
    } finally {
        Pop-Location
    }

    Write-Step "Updating Python dependencies"
    & $PipExe install --upgrade pip --quiet
    & $PipExe install -r $ReqFile --quiet
    Write-Ok "Dependencies updated"

    Write-Step "Restarting service (DB migration runs on startup)"
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        & $NssmExe restart $ServiceName
        Start-Sleep -Seconds 4
        Write-Ok "Service status: $(Get-ServiceStatus)"
    } else {
        Write-Warn "Service not registered. Run Install first."
    }
    Write-Host ""
    Write-Ok "Update complete."
    Wait-Enter
}

function Start-Uninstall {
    Write-Banner
    Write-Host "  [ UNINSTALL ]" -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Type YES to confirm uninstall"
    if ($confirm -ne "YES") { Write-Warn "Cancelled."; Wait-Enter; return }

    Write-Step "Stopping and removing service"
    if (Test-Path $NssmExe) {
        & $NssmExe stop   $ServiceName confirm 2>$null
        & $NssmExe remove $ServiceName confirm 2>$null
        Write-Ok "Service removed"
    } else {
        Write-Warn "NSSM not found - skipping service removal"
    }

    Write-Step "Removing firewall rules"
    Remove-NetFirewallRule -DisplayName "Syslog UDP $SyslogPort"    -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Syslog TCP $SyslogPort"    -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "SIEM Web Console $WebPort" -ErrorAction SilentlyContinue
    Write-Ok "Firewall rules removed"

    Write-Warn "Venv, data, and .env were NOT deleted (your logs are safe)."
    Write-Warn "Delete the syslog_service folder manually to remove everything."
    Wait-Enter
}

function Open-Console {
    Start-Process "http://localhost:$WebPort"
}

function Show-Status {
    Write-Banner
    Write-Host "  [ SERVICE STATUS ]" -ForegroundColor Cyan
    Write-Host ""
    $svcStatus = Get-ServiceStatus
    $col = if ($svcStatus -eq 'Running') { 'Green' } else { 'Yellow' }
    Write-Host "  Service: $ServiceName" -ForegroundColor White
    Write-Host "  Status : $svcStatus" -ForegroundColor $col
    Write-Host ""

    $logFile = Join-Path $LogDir "service.log"
    if (Test-Path $logFile) {
        Write-Host "  Last 20 log lines:" -ForegroundColor Gray
        Write-Host "  ------------------------------------------" -ForegroundColor Gray
        Get-Content $logFile -Tail 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    } else {
        Write-Warn "No log file yet at $logFile"
    }
    Wait-Enter
}

function Edit-EnvFile {
    if (-not (Test-Path $EnvFile)) { Initialize-EnvFile }
    Start-Process notepad $EnvFile
    Write-Host "  Restart the service after saving changes." -ForegroundColor Yellow
    Wait-Enter
}

# ---- Main menu loop ----

while ($true) {
    Write-Banner
    $svcStatus = Get-ServiceStatus
    $col = if ($svcStatus -eq 'Running') { 'Green' } else { 'Yellow' }
    Write-Host "  Service status: " -NoNewline
    Write-Host $svcStatus -ForegroundColor $col
    Write-Host ""
    Write-Host "  1. Install / Repair" -ForegroundColor White
    Write-Host "  2. Update (pull latest + restart)" -ForegroundColor White
    Write-Host "  3. Uninstall" -ForegroundColor White
    Write-Host "  4. Open web console (http://localhost:$WebPort)" -ForegroundColor White
    Write-Host "  5. View service status and logs" -ForegroundColor White
    Write-Host "  6. Edit .env configuration" -ForegroundColor White
    Write-Host "  7. Exit" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "  Select option"

    switch ($choice) {
        '1' { Start-Install }
        '2' { Start-Update }
        '3' { Start-Uninstall }
        '4' { Open-Console }
        '5' { Show-Status }
        '6' { Edit-EnvFile }
        '7' { exit 0 }
        default { Write-Warn "Invalid choice"; Start-Sleep -Seconds 1 }
    }
}
