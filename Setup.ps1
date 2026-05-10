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
$EnvExample   = Join-Path $ScriptDir ".env.example"
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

function Initialize-EnvFile {
    if (Test-Path $EnvFile) { return }
    if (Test-Path $EnvExample) {
        Copy-Item $EnvExample $EnvFile
    } else {
        $secret = [System.BitConverter]::ToString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).Replace("-","").ToLower()
        $content = @"
SECRET_KEY=$secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme
ANTHROPIC_API_KEY=
SYSLOG_UDP_PORT=514
SYSLOG_TCP_PORT=514
API_PORT=8080
RETENTION_DAYS=90
"@
        Set-Content $EnvFile $content -Encoding UTF8
    }
    Write-Warn ".env created - opening for you to configure now."
    Write-Warn "Set ADMIN_PASSWORD and ANTHROPIC_API_KEY at minimum."
    Start-Process notepad $EnvFile -Wait
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
