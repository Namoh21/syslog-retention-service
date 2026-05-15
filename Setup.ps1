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
    Requires: Python 3.10+ and Git only. No external downloads needed.
    Run as Administrator from the syslog_service directory.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$ServiceName  = "SyslogRetentionSvc"
$ScriptDir    = $PSScriptRoot
$VenvDir      = Join-Path $ScriptDir ".venv"
$PythonExe    = Join-Path $VenvDir "Scripts\python.exe"
$PipExe       = Join-Path $VenvDir "Scripts\pip.exe"
$SvcScript    = Join-Path $ScriptDir "windows_service.py"
$LogDir       = Join-Path $ScriptDir "logs"
$DataDir      = Join-Path $ScriptDir "data"
$EnvFile      = Join-Path $ScriptDir ".env"
$ReqFile      = Join-Path $ScriptDir "requirements.txt"
$SyslogPort   = 514
$WebPort      = 8080

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
    # Refresh PATH from registry so installs done in this session are found
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:PATH    = "$machinePath;$userPath"

    # The WindowsApps stub opens the Store instead of running Python - skip it
    foreach ($name in @("python", "python3", "py")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $src = $cmd.Source
        if ($src -like "*WindowsApps*") { continue }
        $ver = & $src --version 2>&1
        if ($ver -match "Python \d") { return $src }
    }

    # Search common install locations (user + system, versions 3.10-3.13)
    $roots = @(
        "$env:LOCALAPPDATA\Programs\Python",
        "C:\Python",
        "C:\Program Files\Python",
        "C:\Program Files (x86)\Python",
        "$env:ProgramFiles\Python"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -Filter "Python3*" -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object {
                $p = Join-Path $_.FullName "python.exe"
                if (Test-Path $p) {
                    $ver = & $p --version 2>&1
                    if ($ver -match "Python 3\.(1[0-9]|[2-9]\d)") { return $p }
                }
            }
    }

    # py launcher (installed by official Python installer)
    $pyLauncher = "C:\Windows\py.exe"
    if (Test-Path $pyLauncher) {
        $resolved = & $pyLauncher -3 -c "import sys; print(sys.executable)" 2>&1
        if ($resolved -and (Test-Path $resolved)) { return $resolved }
    }

    return $null
}


function Install-Python {
    $pythonVersion = "3.12.10"
    $installerUrl  = "https://www.python.org/ftp/python/${pythonVersion}/python-${pythonVersion}-amd64.exe"
    $installerPath = "$env:TEMP\python-installer.exe"

    Write-Host ""
    Write-Host "  Python 3.10+ is required but was not found." -ForegroundColor Yellow
    Write-Host "  This installer can download and install Python $pythonVersion automatically."
    Write-Host ""
    $ans = Read-Host "  Download and install Python $pythonVersion now? (yes/no)"
    if ($ans -ne "yes" -and $ans -ne "y") {
        Write-Warn "Skipped. Install Python manually from https://python.org/downloads"
        return $false
    }

    Write-Step "Downloading Python $pythonVersion (~28 MB)..."
    try {
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
    } catch {
        Write-Err "Download failed: $_"
        Write-Warn "Install manually from https://python.org/downloads"
        return $false
    }
    Write-Ok "Downloaded to $installerPath"

    Write-Step "Installing Python $pythonVersion (silent, all users, with PATH)..."
    # /quiet        = no UI
    # InstallAllUsers=1  = install for all users (requires admin)
    # PrependPath=1      = add to PATH
    # Include_launcher=1 = install py.exe launcher
    $installArgs = "/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1 Include_test=0"
    $proc = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

    if ($proc.ExitCode -ne 0) {
        Write-Err "Python installer exited with code $($proc.ExitCode)"
        return $false
    }
    Write-Ok "Python $pythonVersion installed"

    # Reload PATH from registry so we find it immediately
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:PATH    = "$machinePath;$userPath"

    return $true
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
    Write-Host "  UDP 514 is standard syslog. TCP 6514 avoids privileged-port issues." -ForegroundColor Gray
    Write-Host "  On your UDM: Settings > System > Logging > Remote Syslog." -ForegroundColor Gray
    $udpPort = Read-EnvInput "Syslog UDP port" "514"
    $tcpPort = Read-EnvInput "Syslog TCP port" "6514"
    Write-Host "  Restrict which IPs can send logs (recommended). Leave blank to allow all." -ForegroundColor Gray
    Write-Host "  Example: 192.168.1.0/24" -ForegroundColor Gray
    $allowedSources = Read-EnvInput "Allowed syslog source CIDRs" ""

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
# SECURITY NOTE: ADMIN_PASSWORD and EXTERNAL_API_KEYS are read once on first
# startup to seed the database, then replaced with a sentinel value so this
# file no longer contains plaintext credentials. Manage users and API keys
# via the web console after first run.

SECRET_KEY=$secret
ADMIN_USERNAME=$adminUser
ADMIN_PASSWORD=$adminPass

ANTHROPIC_API_KEY=$anthropicKey
CLAUDE_MODEL=$claudeModel

SYSLOG_UDP_PORT=$udpPort
SYSLOG_TCP_PORT=$tcpPort
ALLOWED_SYSLOG_SOURCES=$allowedSources

API_HOST=$apiHost
API_PORT=$apiPort

RETENTION_DAYS=$retDays
MAX_LOG_ENTRIES=$maxEntries

EXTERNAL_API_KEYS=$extKeys
"@
    Set-Content $EnvFile $envContent -Encoding UTF8

    # Restrict .env to current user only (remove Everyone/Users inheritance)
    try {
        $acl = Get-Acl $EnvFile
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl $EnvFile $acl
        Write-Ok ".env permissions restricted to current user only"
    } catch {
        Write-Warn "Could not restrict .env permissions: $_"
    }

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
        $installed = Install-Python
        if ($installed) {
            $pyPath = Get-PythonPath
        }
        if (-not $pyPath) {
            Write-Err "Python still not found after install attempt."
            Write-Host "  Please install manually from https://python.org/downloads" -ForegroundColor Yellow
            Write-Host "  Check 'Add python.exe to PATH', then re-run Setup.ps1." -ForegroundColor Yellow
            Wait-Enter
            return
        }
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
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $PythonExe)) {
            Write-Err "Venv creation failed. Check that Python 3.10+ is properly installed."
            Wait-Enter; return
        }
        Write-Ok "Venv created"
    } else {
        Write-Ok "Venv already exists"
    }

    Write-Step "Installing Python dependencies (this may take a minute)..."
    & $PipExe install --upgrade pip --quiet
    & $PipExe install -r $ReqFile
    if ($LASTEXITCODE -ne 0) {
        Write-Err "pip install failed - see errors above."
        Wait-Enter; return
    }
    Write-Ok "Dependencies installed"

    New-Item -ItemType Directory -Force -Path $LogDir  | Out-Null
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

    Write-Step "Registering Windows service"
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Service already registered - removing and re-registering"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & $PythonExe $SvcScript remove 2>$null
        Start-Sleep -Seconds 2
    }
    & $PythonExe $SvcScript --startup auto install
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Service registration failed - see errors above."
        Wait-Enter; return
    }
    Set-Service -Name $ServiceName -DisplayName "Syslog Retention and SIEM Service" -Description "Syslog receiver and SIEM for Unifi Dream Machine. Web console on port $WebPort." -ErrorAction SilentlyContinue
    Write-Ok "Service registered"

    Write-Step "Configuring Windows Firewall"
    Set-FirewallRules

    Write-Step "Starting service"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svcStatus = Get-ServiceStatus
    if ($svcStatus -eq 'Running') {
        Write-Ok "Service status: $svcStatus"
    } else {
        Write-Err "Service status: $svcStatus - check logs with option 7 (Diagnostics)"
    }

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
    if (Test-Path $PipExe) {
        & $PipExe install --upgrade pip --quiet
        & $PipExe install -r $ReqFile --quiet
        Write-Ok "Dependencies updated"
    } else {
        Write-Warn "Venv not found - skipping pip update (run Install first)"
    }

    Write-Step "Restarting service (DB migration runs on startup)"
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 4
        Write-Ok "Service status: $(Get-ServiceStatus)"
    } else {
        Write-Warn "Service not registered. Run Install first."
    }

    # Reload this script if Setup.ps1 itself was updated by the pull
    Write-Host ""
    Write-Ok "Update complete."
    Write-Host "  Setup.ps1 was updated - reloading now..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    & powershell.exe -NoExit -ExecutionPolicy Bypass -File "$PSCommandPath"
    exit 0
}

function Start-Uninstall {
    Write-Banner
    Write-Host "  [ UNINSTALL ]" -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Type YES to confirm uninstall"
    if ($confirm -ne "YES") { Write-Warn "Cancelled."; Wait-Enter; return }

    Write-Step "Stopping and removing service"
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & $PythonExe $SvcScript remove 2>$null
        Write-Ok "Service removed"
    } else {
        Write-Warn "Service not found - may already be uninstalled"
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

function Start-Diagnostics {
    Write-Banner
    Write-Host "  [ DIAGNOSTICS ]" -ForegroundColor Cyan
    Write-Host ""

    # 1. Service status
    Write-Host "  -- Windows Service --" -ForegroundColor Cyan
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        $col = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
        Write-Host "  Status : $($svc.Status)" -ForegroundColor $col
        Write-Host "  Start  : $($svc.StartType)"
    } else {
        Write-Host "  Service NOT installed" -ForegroundColor Red
    }

    # 2. Python / venv
    Write-Host ""
    Write-Host "  -- Python Environment --" -ForegroundColor Cyan
    if (Test-Path $PythonExe) {
        $ver = & $PythonExe --version 2>&1
        Write-Host "  Venv Python : $ver" -ForegroundColor Green
    } else {
        Write-Host "  Venv Python NOT found at $PythonExe" -ForegroundColor Red
        Write-Host "  Run Install to create the venv." -ForegroundColor Yellow
    }

    # 3. Key files
    Write-Host ""
    Write-Host "  -- Key Files --" -ForegroundColor Cyan
    $files = @{
        "main.py"            = (Join-Path $ScriptDir "main.py")
        "windows_service.py" = (Join-Path $ScriptDir "windows_service.py")
        ".env"               = $EnvFile
        "requirements.txt"   = $ReqFile
    }
    foreach ($name in $files.Keys) {
        $exists = Test-Path $files[$name]
        $col = if ($exists) { 'Green' } else { 'Red' }
        $label = if ($exists) { "OK" } else { "MISSING" }
        Write-Host "  $label  $name" -ForegroundColor $col
    }

    # 4. Port check
    Write-Host ""
    Write-Host "  -- Port Availability --" -ForegroundColor Cyan
    foreach ($port in @($WebPort, $SyslogPort)) {
        $inUse = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        if ($inUse) {
            Write-Host "  Port $port : IN USE (pid $($inUse[0].OwningProcess))" -ForegroundColor Green
        } else {
            $udpInUse = Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue
            if ($udpInUse) {
                Write-Host "  Port $port : IN USE UDP (pid $($udpInUse[0].OwningProcess))" -ForegroundColor Green
            } else {
                Write-Host "  Port $port : not listening" -ForegroundColor Yellow
            }
        }
    }

    # 5. Firewall rules
    Write-Host ""
    Write-Host "  -- Firewall Rules --" -ForegroundColor Cyan
    $rules = @("Syslog UDP $SyslogPort", "Syslog TCP $SyslogPort", "SIEM Web Console $WebPort")
    foreach ($rule in $rules) {
        $r = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
        if ($r) {
            $col = if ($r.Enabled -eq 'True') { 'Green' } else { 'Yellow' }
            Write-Host "  $($r.Enabled)   $rule" -ForegroundColor $col
        } else {
            Write-Host "  MISSING  $rule" -ForegroundColor Red
        }
    }

    # 6. Recent log output
    Write-Host ""
    Write-Host "  -- Recent Log Output --" -ForegroundColor Cyan
    $logFile = Join-Path $LogDir "service.log"
    $errFile = Join-Path $LogDir "service_err.log"
    if (Test-Path $errFile) {
        $errLines = Get-Content $errFile -Tail 10 -ErrorAction SilentlyContinue
        if ($errLines) {
            Write-Host "  service_err.log (last 10 lines):" -ForegroundColor Yellow
            $errLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
    }
    if (Test-Path $logFile) {
        Write-Host "  service.log (last 15 lines):" -ForegroundColor Gray
        Get-Content $logFile -Tail 15 | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    } else {
        Write-Warn "No log file yet - service may not have started successfully"
    }

    # 7. Offer test run
    Write-Host ""
    Write-Host "  -- Test Run --" -ForegroundColor Cyan
    Write-Host "  You can test the app directly (outside the service) to see errors live."
    $run = Read-Host "  Run app now in this window for 30 seconds? (yes/no)"
    if ($run -eq 'yes' -or $run -eq 'y') {
        # Resolve which Python to use
        $testPy = $null
        if (Test-Path $PythonExe) {
            $testPy = $PythonExe
        } else {
            $sysPy = Get-Command python -ErrorAction SilentlyContinue
            if ($sysPy) { $testPy = $sysPy.Source }
        }
        if (-not $testPy) {
            Write-Err "No Python found. Run Install first."
        } else {
            Write-Host ""
            Write-Host "  Using Python: $testPy" -ForegroundColor Gray
            Write-Host "  Starting app - watch for errors below:" -ForegroundColor Yellow
            Write-Host ""
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $proc = Start-Process -FilePath $testPy `
                -ArgumentList (Join-Path $ScriptDir "main.py") `
                -WorkingDirectory $ScriptDir `
                -NoNewWindow -PassThru
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
                Start-Sleep -Seconds 1
            }
            if (-not $proc.HasExited) { $proc.Kill() }
            Write-Host ""
            Write-Host "  Test run finished (exit code: $($proc.ExitCode))." -ForegroundColor Yellow
            Write-Host "  Check the output above for errors." -ForegroundColor Yellow
            Write-Host "  NOTE: Run Install first if venv was missing." -ForegroundColor Cyan
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
    }

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
    Write-Host "  7. Diagnostics and test run" -ForegroundColor White
    Write-Host "  8. Exit" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "  Select option"

    switch ($choice) {
        '1' { Start-Install }
        '2' { Start-Update }
        '3' { Start-Uninstall }
        '4' { Open-Console }
        '5' { Show-Status }
        '6' { Edit-EnvFile }
        '7' { Start-Diagnostics }
        '8' { exit 0 }
        default { Write-Warn "Invalid choice"; Start-Sleep -Seconds 1 }
    }
}
