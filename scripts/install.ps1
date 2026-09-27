<#
.SYNOPSIS
    AISRF installer for Windows: downloads the latest self-contained release, verifies its SHA256,
    unpacks it to %LOCALAPPDATA%\Programs\AISRF and adds that folder to the user PATH.

.DESCRIPTION
    One-liner (PowerShell 5.1 or 7):
      irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1 | iex
    Or with options:
      & ([scriptblock]::Create((irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1))) -Version 1.2.0

    Environment overrides: AISRF_VERSION (default latest), AISRF_REPO (default keyuraghao/aisrf),
    AISRF_INSTALL_DIR (default %LOCALAPPDATA%\Programs\AISRF).

.PARAMETER Version
    Release version to install, e.g. 1.2.0. Default: latest.
.PARAMETER InstallDir
    Destination folder. Default: %LOCALAPPDATA%\Programs\AISRF.
.PARAMETER NoPath
    Do not modify the user PATH.
#>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:AISRF_VERSION) { $env:AISRF_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:AISRF_INSTALL_DIR) { $env:AISRF_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\AISRF" }),
    [string]$Repo = $(if ($env:AISRF_REPO) { $env:AISRF_REPO } else { "keyuraghao/aisrf" }),
    [switch]$NoPath
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Say([string]$msg) { Write-Host "[aisrf] $msg" -ForegroundColor Cyan }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x86_64" }
    "ARM64" { "arm64" }
    default { throw "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
if ($arch -eq "arm64") {
    Say "no native arm64 Windows build is published yet; installing the x86_64 build (runs under emulation)"
    $arch = "x86_64"
}

$headers = @{ "User-Agent" = "aisrf-install.ps1" }
if ($Version -eq "latest") {
    Say "resolving the latest release of $Repo"
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    $Version = $release.tag_name -replace "^v", ""
}
$Version = $Version -replace "^v", ""

$archive = "aisrf-$Version-windows-$arch.zip"
$sums = "SHA256SUMS-windows-$arch.txt"
$base = "https://github.com/$Repo/releases/download/v$Version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("aisrf-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    Say "downloading $archive (v$Version)"
    Invoke-WebRequest -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive) -Headers $headers -UseBasicParsing
    Invoke-WebRequest -Uri "$base/$sums" -OutFile (Join-Path $tmp $sums) -Headers $headers -UseBasicParsing

    Say "verifying SHA256"
    $line = Get-Content (Join-Path $tmp $sums) | Where-Object { $_ -match "\s$([regex]::Escape($archive))$" } | Select-Object -First 1
    if (-not $line) { throw "$archive is not listed in $sums" }
    $expected = ($line -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "checksum mismatch: expected $expected got $actual" }

    Say "installing to $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $target = Join-Path $InstallDir "aisrf"
    if (Test-Path $target) {
        $running = Get-Process -Name aisrf -ErrorAction SilentlyContinue
        if ($running) { throw "aisrf.exe is running; stop it (or the AISRF service) and run the installer again" }
        Remove-Item -Recurse -Force $target
    }
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $InstallDir -Force
    Unblock-File -Path (Join-Path $target "aisrf.exe") -ErrorAction SilentlyContinue
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    if (($userPath -split ";") -notcontains $target) {
        [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $target).TrimStart(";"), "User")
        Say "added $target to the user PATH (open a new terminal to pick it up)"
    }
    if (($env:Path -split ";") -notcontains $target) { $env:Path = "$env:Path;$target" }
}

$exe = Join-Path $target "aisrf.exe"
$installed = & $exe version
Say "installed $installed -> $exe"

Write-Host ""
Write-Host "Next steps:"
Write-Host "  aisrf desktop            # local dashboard on 127.0.0.1, opens a window or your browser"
Write-Host "  aisrf serve              # gateway on 0.0.0.0:8080 (set AISRF_HOST / AISRF_PORT)"
Write-Host "  aisrf --help"
Write-Host ""
Write-Host "State (SQLite, logs) and the generated settings file aisrf.env with a random secret key and"
Write-Host "admin API token live in $env:LOCALAPPDATA\AISRF; set AISRF_HOME to relocate them."
Write-Host "Sign in with admin / admin and change the password immediately."
Write-Host "Windows service: deploy\windows\install-service.ps1 in the repository."
Write-Host "Uninstall: remove $InstallDir and $env:LOCALAPPDATA\AISRF, then drop $target from your PATH."
