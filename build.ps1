<#
.SYNOPSIS
    Build the warpscan binary for Windows and/or Linux.

.DESCRIPTION
    Wraps `cargo build` for the native Windows target and, via WSL, the Linux
    (x86_64-unknown-linux-gnu) target. The Linux build uses a separate
    CARGO_TARGET_DIR (target-linux) so it never collides with the Windows
    artifacts in target/.

    Building only needs crates.io (reachable on a DPI'd network). The Rust
    *toolchain* itself is not downloaded here; update it separately if needed.

.PARAMETER Target
    Which target(s) to build: windows, linux, or all. Default: all.

.PARAMETER Dev
    Build the debug profile instead of release.

.EXAMPLE
    .\build.ps1
    Builds both Windows and Linux release binaries.

.EXAMPLE
    .\build.ps1 -Target linux
    Builds only the Linux binary via WSL.
#>
[CmdletBinding()]
param(
    [ValidateSet('windows', 'linux', 'all')]
    [string]$Target = 'all',

    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$profileName = if ($Dev) { 'debug' } else { 'release' }
$profileFlag = if ($Dev) { '' } else { '--release' }

function Convert-ToWslPath {
    param([string]$WindowsPath)
    $full = (Resolve-Path $WindowsPath).Path
    $drive = $full.Substring(0, 1).ToLower()
    $rest = $full.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$rest"
}

function Build-Windows {
    Write-Host "==> Building Windows ($profileName)..." -ForegroundColor Cyan
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found on PATH. Install Rust from https://rustup.rs first."
    }
    $cargoArgs = @('build')
    if (-not $Dev) { $cargoArgs += '--release' }
    Push-Location $projectRoot
    try {
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "Windows build failed (exit $LASTEXITCODE)." }
    }
    finally { Pop-Location }

    $bin = Join-Path $projectRoot "target\$profileName\warpscan.exe"
    if (Test-Path $bin) {
        $size = "{0:N1} MB" -f ((Get-Item $bin).Length / 1MB)
        Write-Host "    Windows binary: $bin ($size)" -ForegroundColor Green
    }
}

function Build-Linux {
    Write-Host "==> Building Linux ($profileName) via WSL..." -ForegroundColor Cyan
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
        throw "wsl not found. Install WSL (with a distro that has Rust) to build for Linux."
    }
    $wslRoot = Convert-ToWslPath $projectRoot
    $cmd = "cd '$wslRoot' && CARGO_TARGET_DIR=target-linux cargo build $profileFlag"
    & wsl bash -lc $cmd
    if ($LASTEXITCODE -ne 0) { throw "Linux build failed (exit $LASTEXITCODE)." }

    $bin = Join-Path $projectRoot "target-linux\$profileName\warpscan"
    if (Test-Path $bin) {
        $size = "{0:N1} MB" -f ((Get-Item $bin).Length / 1MB)
        Write-Host "    Linux binary:   $bin ($size)" -ForegroundColor Green
    }
}

switch ($Target) {
    'windows' { Build-Windows }
    'linux'   { Build-Linux }
    'all'     { Build-Windows; Build-Linux }
}

Write-Host "Done." -ForegroundColor Cyan
