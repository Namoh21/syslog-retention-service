#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Updates the Syslog Retention Service in-place from GitHub.

.DESCRIPTION
    1. Pulls the latest code from origin/main.
    2. Installs any new Python dependencies.
    3. Restarts the Windows service.
    4. Runs the DB migration (new columns added automatically on startup).

.PARAMETER Branch
    Git branch to pull from. Default: main

.EXAMPLE
    .\update.ps1
    .\update.ps1 -Branch dev
#>
param(
    [string]$Branch = "main"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = "SyslogRetentionSvc"
$ScriptDir   = $PSScriptRoot
$VenvPip     = Join-Path $ScriptDir ".venv\Scripts\pip.exe"
$NssmExe     = Join-Path $ScriptDir "tools\nssm\win64\nssm.exe"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    WARN: $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Syslog Retention Service — Updater" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# ---- Git pull ----
Write-Step "Pulling latest code from branch '$Branch'"
Push-Location $ScriptDir
try {
    $gitStatus = git status --porcelain 2>&1
    if ($gitStatus) {
        Write-Warn "You have local modifications. Stashing them before pull."
        git stash push -m "auto-stash before update $(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    git fetch origin
    git checkout $Branch
    git pull origin $Branch
    Write-Ok "Code updated"
} finally {
    Pop-Location
}

# ---- Python deps ----
Write-Step "Updating Python dependencies"
if (Test-Path $VenvPip) {
    & $VenvPip install --upgrade pip --quiet
    & $VenvPip install -r (Join-Path $ScriptDir "requirements.txt") --quiet
    Write-Ok "Dependencies updated"
} else {
    Write-Warn "Venv not found at expected path. Run install_service.ps1 first."
    exit 1
}

# ---- Restart service ----
Write-Step "Restarting service (DB migration runs automatically on startup)"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    & $NssmExe restart $ServiceName
    Start-Sleep -Seconds 4
    $svc.Refresh()
    Write-Ok "Service status: $($svc.Status)"
} else {
    Write-Warn "Service '$ServiceName' not found. Run install_service.ps1 to register it."
}

Write-Host ""
Write-Host "  Update complete!" -ForegroundColor Green
Write-Host "  Web console: http://localhost:8080" -ForegroundColor Green
Write-Host ""
