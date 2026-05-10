#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (or uninstalls) the Syslog Retention Service as a Windows service using NSSM.

.DESCRIPTION
    1. Downloads NSSM if not present.
    2. Creates a Python venv, installs requirements.
    3. Registers the service to auto-start at boot.
    4. Opens Windows Firewall for syslog UDP/TCP 514 and the web console port.

.PARAMETER Uninstall
    Remove the service instead of installing it.

.EXAMPLE
    .\install_service.ps1
    .\install_service.ps1 -Uninstall
#>
param(
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Config ----
$ServiceName   = "SyslogRetentionSvc"
$DisplayName   = "Syslog Retention & SIEM Service"
$ScriptDir     = $PSScriptRoot
$VenvDir       = Join-Path $ScriptDir ".venv"
$PythonExe     = Join-Path $VenvDir "Scripts\python.exe"
$MainScript    = Join-Path $ScriptDir "main.py"
$NssmDir       = Join-Path $ScriptDir "tools\nssm"
$NssmExe       = Join-Path $NssmDir "win64\nssm.exe"
$NssmZip       = Join-Path $ScriptDir "tools\nssm.zip"
$NssmUrl       = "https://nssm.cc/release/nssm-2.24.zip"
$LogDir        = Join-Path $ScriptDir "logs"
$SyslogPort    = 514
$WebPort       = 8080

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    WARN: $msg" -ForegroundColor Yellow }

# ======================================================
# UNINSTALL
# ======================================================
if ($Uninstall) {
    Write-Step "Stopping and removing service '$ServiceName'"
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        & $NssmExe stop $ServiceName confirm 2>$null
        & $NssmExe remove $ServiceName confirm
        Write-Ok "Service removed"
    } else {
        Write-Warn "Service not found"
    }
    Write-Step "Removing firewall rules"
    Remove-NetFirewallRule -DisplayName "Syslog UDP $SyslogPort" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Syslog TCP $SyslogPort" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "SIEM Web Console $WebPort" -ErrorAction SilentlyContinue
    Write-Ok "Done. Venv and data files were NOT removed."
    exit 0
}

# ======================================================
# INSTALL
# ======================================================

Write-Step "Checking .env file"
$EnvFile = Join-Path $ScriptDir ".env"
if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $ScriptDir ".env.example") $EnvFile
    Write-Warn ".env created from .env.example — EDIT IT before starting the service!"
    Write-Warn "Especially: SECRET_KEY, ADMIN_PASSWORD, ANTHROPIC_API_KEY"
    notepad $EnvFile
    Read-Host "Press Enter once you have saved your .env settings"
}

Write-Step "Locating Python 3.10+"
$PythonSystem = (Get-Command python -ErrorAction SilentlyContinue)?.Source
if (-not $PythonSystem) {
    Write-Error "Python not found in PATH. Install Python 3.10+ from python.org and re-run."
}
$PythonVer = & $PythonSystem -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Ok "Found Python $PythonVer at $PythonSystem"

Write-Step "Creating virtual environment"
if (-not (Test-Path $VenvDir)) {
    & $PythonSystem -m venv $VenvDir
    Write-Ok "Venv created at $VenvDir"
} else {
    Write-Ok "Venv already exists"
}

Write-Step "Installing Python dependencies"
& $PythonExe -m pip install --upgrade pip --quiet
& $PythonExe -m pip install -r (Join-Path $ScriptDir "requirements.txt") --quiet
Write-Ok "Dependencies installed"

Write-Step "Creating log directory"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ScriptDir "data") | Out-Null
Write-Ok "Directories ready"

Write-Step "Downloading NSSM (service wrapper)"
if (-not (Test-Path $NssmExe)) {
    New-Item -ItemType Directory -Force -Path (Join-Path $ScriptDir "tools") | Out-Null
    Write-Host "    Downloading from $NssmUrl …"
    Invoke-WebRequest -Uri $NssmUrl -OutFile $NssmZip -UseBasicParsing
    Expand-Archive -Path $NssmZip -DestinationPath (Join-Path $ScriptDir "tools") -Force
    # NSSM archive unpacks as nssm-2.24\win64\nssm.exe
    $extracted = Get-ChildItem (Join-Path $ScriptDir "tools") -Filter "nssm*" -Directory | Select-Object -First 1
    if ($extracted) { Rename-Item $extracted.FullName $NssmDir -ErrorAction SilentlyContinue }
    Remove-Item $NssmZip -Force -ErrorAction SilentlyContinue
    Write-Ok "NSSM ready at $NssmExe"
} else {
    Write-Ok "NSSM already present"
}

Write-Step "Registering Windows service"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Warn "Service already exists — stopping and reconfiguring"
    & $NssmExe stop $ServiceName confirm 2>$null
    & $NssmExe remove $ServiceName confirm
}

& $NssmExe install $ServiceName $PythonExe
& $NssmExe set     $ServiceName AppParameters $MainScript
& $NssmExe set     $ServiceName AppDirectory  $ScriptDir
& $NssmExe set     $ServiceName DisplayName   $DisplayName
& $NssmExe set     $ServiceName Description   "Receives syslog from Unifi/network devices; provides AI-powered SIEM via Claude."
& $NssmExe set     $ServiceName Start         SERVICE_AUTO_START
& $NssmExe set     $ServiceName AppStdout     (Join-Path $LogDir "service.log")
& $NssmExe set     $ServiceName AppStderr     (Join-Path $LogDir "service_err.log")
& $NssmExe set     $ServiceName AppRotateFiles 1
& $NssmExe set     $ServiceName AppRotateBytes 10485760
Write-Ok "Service registered"

Write-Step "Configuring Windows Firewall"
$fwParams = @{ Protocol='UDP'; LocalPort=$SyslogPort; Action='Allow'; Profile='Private,Domain' }
New-NetFirewallRule -DisplayName "Syslog UDP $SyslogPort" -Direction Inbound @fwParams -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Syslog TCP $SyslogPort" -Direction Inbound -Protocol TCP -LocalPort $SyslogPort -Action Allow -Profile Private,Domain -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "SIEM Web Console $WebPort" -Direction Inbound -Protocol TCP -LocalPort $WebPort -Action Allow -Profile Private,Domain -ErrorAction SilentlyContinue | Out-Null
Write-Ok "Firewall rules added (Private + Domain profiles)"

Write-Step "Starting service"
& $NssmExe start $ServiceName
Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName
Write-Ok "Service status: $($svc.Status)"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "  Web console : http://localhost:$WebPort" -ForegroundColor Green
Write-Host "  Syslog UDP  : port $SyslogPort" -ForegroundColor Green
Write-Host "  Syslog TCP  : port $SyslogPort" -ForegroundColor Green
Write-Host "  Default login: admin / (see .env ADMIN_PASSWORD)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Point your Unifi Dream Machine syslog target to this PC's IP on port $SyslogPort"
Write-Host "  2. Open http://localhost:$WebPort and change the admin password"
Write-Host "  3. Generate an API key for Claude Projects under the API Keys tab"
Write-Host "  4. Add your Anthropic API key to .env to enable AI analysis"
Write-Host ""
