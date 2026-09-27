<#
.SYNOPSIS
    Install the AISRF gateway as a Windows service.

.DESCRIPTION
    Two mechanisms are supported and chosen automatically:

    1. NSSM (https://nssm.cc), when nssm.exe is on PATH or passed with -Nssm. NSSM wraps the
       console binary, restarts it on failure, rotates stdout/stderr logs and stores the AISRF_*
       environment in the service's own registry key (AppEnvironmentExtra). Recommended.

    2. sc.exe create with a generated wrapper .cmd (no third party tool). Windows services must
       report to the Service Control Manager; a plain console binary started by sc.exe is killed
       after 30 s. The wrapper therefore registers the service through `sc.exe create ... binPath=`
       pointing at cmd.exe /c <wrapper>, and the environment is written to
       HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment (REG_MULTI_SZ), which the SCM
       injects into the process. Use this only when NSSM cannot be installed; the process is not
       supervised as tightly and you should pair it with the service recovery options set below.

    The settings file %ProgramData%\AISRF\aisrf.env is created on first run with a random
    AISRF_SECRET_KEY and AISRF_ADMIN_API_TOKEN (the binary generates it when AISRF_HOME is set).

.PARAMETER Binary
    Path to aisrf.exe. Default: %LOCALAPPDATA%\Programs\AISRF\aisrf\aisrf.exe (scripts/install.ps1).
.PARAMETER Name
    Service name. Default AISRF.
.PARAMETER Home
    AISRF_HOME (data, logs, SQLite file, aisrf.env). Default %ProgramData%\AISRF.
.PARAMETER Port
    Listening port. Default 8080. The service binds to 127.0.0.1; put IIS/nginx/Caddy in front for TLS.
.PARAMETER Nssm
    Path to nssm.exe (optional, auto-detected on PATH).
.PARAMETER ForceSc
    Use sc.exe even when NSSM is available.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File deploy\windows\install-service.ps1
    powershell -ExecutionPolicy Bypass -File deploy\windows\install-service.ps1 -Binary "C:\aisrf\aisrf.exe" -Port 9000
#>
[CmdletBinding()]
param(
    [string]$Binary = (Join-Path $env:LOCALAPPDATA "Programs\AISRF\aisrf\aisrf.exe"),
    [string]$Name = "AISRF",
    [string]$Home = (Join-Path $env:ProgramData "AISRF"),
    [int]$Port = 8080,
    [string]$BindHost = "127.0.0.1",
    [string]$Nssm = "",
    [switch]$ForceSc
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated (Administrator) PowerShell."
    }
}

Assert-Admin

if (-not (Test-Path $Binary)) {
    throw "aisrf.exe not found at '$Binary'. Install it first (scripts\install.ps1) or pass -Binary."
}
$Binary = (Resolve-Path $Binary).Path

New-Item -ItemType Directory -Force -Path $Home | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Home "data") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Home "logs") | Out-Null

$dataDir = Join-Path $Home "data"
$logDir = Join-Path $Home "logs"
$dbPath = (Join-Path $dataDir "aisrf.db") -replace "\\", "/"
$envVars = [ordered]@{
    "AISRF_HOME" = $Home
    "AISRF_DATA_DIR" = $dataDir
    "AISRF_LOG_DIR" = $logDir
    "AISRF_DATABASE_URL" = "sqlite+aiosqlite:///$dbPath"
    "AISRF_ENVIRONMENT" = "production"
    "AISRF_LOG_JSON_CONSOLE" = "true"
    "AISRF_HOST" = $BindHost
    "AISRF_PORT" = "$Port"
}

# First run: let the binary create aisrf.env with a random secret key and admin token.
# (Environment is set on this process; Start-Process -Environment needs PowerShell 7.4.)
foreach ($k in $envVars.Keys) { Set-Item -Path "Env:$k" -Value $envVars[$k] }
& $Binary init-db
if ($LASTEXITCODE -ne 0) {
    throw "aisrf init-db failed with exit code $LASTEXITCODE; check $logDir"
}

# Restrict the settings file to Administrators and SYSTEM (it holds the encryption key and the admin token).
$envFile = Join-Path $Home "aisrf.env"
if (Test-Path $envFile) {
    icacls $envFile /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)" | Out-Null
}

$existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Service '$Name' already exists. Run uninstall-service.ps1 first." -ForegroundColor Yellow
    exit 1
}

if (-not $Nssm) {
    $found = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($found) { $Nssm = $found.Source }
}

if ($Nssm -and -not $ForceSc) {
    Write-Host "Installing '$Name' with NSSM ($Nssm)"
    & $Nssm install $Name $Binary serve
    & $Nssm set $Name AppDirectory $Home
    & $Nssm set $Name DisplayName "AISRF gateway"
    & $Nssm set $Name Description "AI Security & Research Framework: human-in-the-loop LLM gateway"
    & $Nssm set $Name Start SERVICE_AUTO_START
    & $Nssm set $Name AppStdout (Join-Path $logDir "service.out.log")
    & $Nssm set $Name AppStderr (Join-Path $logDir "service.err.log")
    & $Nssm set $Name AppRotateFiles 1
    & $Nssm set $Name AppRotateBytes 52428800
    & $Nssm set $Name AppStopMethodConsole 15000
    & $Nssm set $Name AppExit Default Restart
    & $Nssm set $Name AppRestartDelay 5000
    $pairs = @()
    foreach ($k in $envVars.Keys) { $pairs += "$k=$($envVars[$k])" }
    & $Nssm set $Name AppEnvironmentExtra $pairs
    $method = "nssm"
} else {
    Write-Host "Installing '$Name' with sc.exe and a wrapper script"
    $wrapper = Join-Path $Home "aisrf-service.cmd"
    $lines = @("@echo off", "cd /d `"$Home`"")
    foreach ($k in $envVars.Keys) { $lines += "set $k=$($envVars[$k])" }
    $lines += "`"$Binary`" serve >> `"$logDir\service.out.log`" 2>&1"
    Set-Content -Path $wrapper -Value $lines -Encoding ASCII
    $binPath = "cmd.exe /c `"`"$wrapper`"`""
    sc.exe create $Name binPath= $binPath start= auto DisplayName= "AISRF gateway" obj= LocalSystem | Out-Null
    sc.exe description $Name "AI Security & Research Framework: human-in-the-loop LLM gateway" | Out-Null
    # Also expose the variables through the service's registry Environment value.
    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $multi = @()
    foreach ($k in $envVars.Keys) { $multi += "$k=$($envVars[$k])" }
    New-ItemProperty -Path $regKey -Name Environment -PropertyType MultiString -Value $multi -Force | Out-Null
    $method = "sc"
}

sc.exe failure $Name reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Start-Service -Name $Name
Start-Sleep -Seconds 3
$svc = Get-Service -Name $Name

Write-Host ""
Write-Host "Service '$Name' installed ($method) and $($svc.Status)."
Write-Host "  dashboard : http://$BindHost`:$Port"
Write-Host "  settings  : $envFile  (AISRF_SECRET_KEY, AISRF_ADMIN_API_TOKEN, add AISRF_ADMIN_PASSWORD=...)"
Write-Host "  data/logs : $dataDir , $logDir"
Write-Host "  manage    : Start-Service $Name | Stop-Service $Name | Restart-Service $Name"
Write-Host "Change the admin password before exposing the port (Settings > Reviewers, or AISRF_ADMIN_PASSWORD in aisrf.env)."
