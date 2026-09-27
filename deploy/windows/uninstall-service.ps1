<#
.SYNOPSIS
    Remove the AISRF Windows service installed by install-service.ps1.

.DESCRIPTION
    Stops and deletes the service whether it was created with NSSM or with sc.exe, removes the
    wrapper .cmd and (with -PurgeData) the AISRF_HOME directory, including the SQLite database, the
    logs and aisrf.env. Without -PurgeData the data stays in place for a later reinstall.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall-service.ps1
    powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall-service.ps1 -PurgeData
#>
[CmdletBinding()]
param(
    [string]$Name = "AISRF",
    [string]$Home = (Join-Path $env:ProgramData "AISRF"),
    [string]$Nssm = "",
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}

$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "Service '$Name' is not installed."
} else {
    if ($svc.Status -ne "Stopped") {
        Write-Host "Stopping '$Name' ..."
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    if (-not $Nssm) {
        $found = Get-Command nssm.exe -ErrorAction SilentlyContinue
        if ($found) { $Nssm = $found.Source }
    }
    $usedNssm = $false
    if ($Nssm) {
        $params = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name\Parameters" -ErrorAction SilentlyContinue
        if ($params -and $params.PSObject.Properties.Name -contains "Application") { $usedNssm = $true }
    }
    if ($usedNssm) {
        & $Nssm remove $Name confirm
    } else {
        sc.exe delete $Name | Out-Null
    }
    Write-Host "Service '$Name' removed."
}

$wrapper = Join-Path $Home "aisrf-service.cmd"
if (Test-Path $wrapper) { Remove-Item $wrapper -Force }

if ($PurgeData) {
    if (Test-Path $Home) {
        Remove-Item -Recurse -Force $Home
        Write-Host "Removed $Home (database, logs and aisrf.env)."
    }
} else {
    Write-Host "Data kept in $Home. Re-run with -PurgeData to delete it."
}
