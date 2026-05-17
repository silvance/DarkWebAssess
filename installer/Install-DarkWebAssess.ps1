<#
.SYNOPSIS
    Install the DarkWebAssess Windows bundle for the current user.

.DESCRIPTION
    Copies the PyInstaller-built bundle to %LOCALAPPDATA%\Programs\DarkWebAssess,
    creates Start Menu + Desktop shortcuts, and seeds the per-user data
    directory at %APPDATA%\DarkWebAssess. No admin rights required.

    Run this script from the directory that contains the unzipped
    `mini-threat-intel\` bundle (i.e. the directory with `mini-threat-intel.exe`
    inside `mini-threat-intel\`). For example:

        cd C:\Users\you\Downloads\mini-threat-intel-windows
        powershell -ExecutionPolicy Bypass -File .\installer\Install-DarkWebAssess.ps1

.PARAMETER InstallDir
    Override the install directory. Default: %LOCALAPPDATA%\Programs\DarkWebAssess.

.PARAMETER DataDir
    Override the data directory. Default: %APPDATA%\DarkWebAssess.

.PARAMETER NoShortcuts
    Skip creating Start Menu / Desktop shortcuts.

.PARAMETER NoLaunch
    Don't auto-launch the tray after install.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\DarkWebAssess"),
    [string]$DataDir    = (Join-Path $env:APPDATA "DarkWebAssess"),
    [switch]$NoShortcuts,
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "[install] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[install] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "[install] WARN $msg" -ForegroundColor Yellow }
function Fail($msg)       { Write-Host "[install] ERROR $msg" -ForegroundColor Red; exit 1 }

# --- 1. Locate the bundle to install ----------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir

$BundleCandidates = @(
    Join-Path $RepoRoot "dist\mini-threat-intel",
    Join-Path $RepoRoot "mini-threat-intel",
    Join-Path (Get-Location) "mini-threat-intel",
    Join-Path (Get-Location) "dist\mini-threat-intel"
)
$Bundle = $BundleCandidates | Where-Object { Test-Path (Join-Path $_ "mini-threat-intel.exe") } | Select-Object -First 1
if (-not $Bundle) {
    Fail "Could not find mini-threat-intel.exe in any of:`n  $($BundleCandidates -join "`n  ")"
}
Write-Step "Using bundle: $Bundle"

# --- 2. Stage destination directories ---------------------------------------
Write-Step "Install dir: $InstallDir"
Write-Step "Data dir:    $DataDir"

if (Test-Path $InstallDir) {
    # If the exe is running, this will fail with a clear error.
    Write-Step "Cleaning previous install ..."
    try {
        Remove-Item -Recurse -Force $InstallDir
    } catch {
        Fail "Could not remove $InstallDir (is DarkWebAssess still running?): $_"
    }
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir    | Out-Null

# --- 3. Copy the bundle -----------------------------------------------------
Write-Step "Copying bundle ..."
Copy-Item -Path (Join-Path $Bundle "*") -Destination $InstallDir -Recurse -Force
$Exe = Join-Path $InstallDir "mini-threat-intel.exe"
if (-not (Test-Path $Exe)) {
    Fail "Copy succeeded but $Exe is missing."
}

# --- 4. Write the user environment configuration ----------------------------
# We don't want to pollute the user's global env. Instead, write a tiny
# launcher .cmd that sets DWA_DATA_DIR before invoking the exe.
$LauncherDashboard = Join-Path $InstallDir "DarkWebAssess.cmd"
$LauncherTray      = Join-Path $InstallDir "DarkWebAssess-Tray.cmd"

@"
@echo off
set "DWA_DATA_DIR=$DataDir"
start "" "%~dp0mini-threat-intel.exe" dashboard
"@ | Set-Content -Encoding ASCII $LauncherDashboard

@"
@echo off
set "DWA_DATA_DIR=$DataDir"
start "" "%~dp0mini-threat-intel.exe" tray
"@ | Set-Content -Encoding ASCII $LauncherTray

# --- 5. Shortcuts -----------------------------------------------------------
if (-not $NoShortcuts) {
    Write-Step "Creating shortcuts ..."
    $StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\DarkWebAssess"
    New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
    $Desktop = [Environment]::GetFolderPath("Desktop")

    $shell = New-Object -ComObject WScript.Shell

    function New-Shortcut($lnkPath, $target, $args, $desc, $iconPath) {
        $sc = $shell.CreateShortcut($lnkPath)
        $sc.TargetPath = $target
        $sc.Arguments  = $args
        $sc.WorkingDirectory = $InstallDir
        $sc.Description = $desc
        if ($iconPath) { $sc.IconLocation = $iconPath }
        $sc.Save()
    }

    New-Shortcut `
        (Join-Path $StartMenu "DarkWebAssess Dashboard.lnk") `
        $LauncherDashboard "" "Open the DarkWebAssess threat-intel dashboard" $Exe
    New-Shortcut `
        (Join-Path $StartMenu "DarkWebAssess (Tray).lnk") `
        $LauncherTray "" "Run DarkWebAssess in the system tray" $Exe
    New-Shortcut `
        (Join-Path $StartMenu "Uninstall DarkWebAssess.lnk") `
        "powershell.exe" "-ExecutionPolicy Bypass -File `"$InstallDir\Uninstall-DarkWebAssess.ps1`"" `
        "Uninstall DarkWebAssess" ""
    New-Shortcut `
        (Join-Path $Desktop "DarkWebAssess.lnk") `
        $LauncherDashboard "" "Open the DarkWebAssess dashboard" $Exe
}

# --- 6. Stage the uninstaller alongside the install -------------------------
$Uninst = Join-Path $InstallDir "Uninstall-DarkWebAssess.ps1"
Copy-Item -Path (Join-Path $ScriptDir "Uninstall-DarkWebAssess.ps1") -Destination $Uninst -Force

# --- 7. Initialize the DB so the first launch is fast -----------------------
Write-Step "Initializing database ..."
$env:DWA_DATA_DIR = $DataDir
try {
    & $Exe init-db | Out-Null
    & $Exe sync-config | Out-Null
} catch {
    Write-Warn2 "init-db / sync-config returned non-zero (first launch will retry): $_"
}

Write-Ok "Install complete."
Write-Host ""
Write-Host "  Open the dashboard:  $LauncherDashboard"
Write-Host "  Run in the tray:     $LauncherTray"
Write-Host "  Data directory:      $DataDir"
Write-Host "  Uninstall:           $Uninst"
Write-Host ""

if (-not $NoLaunch) {
    Write-Step "Launching tray ..."
    Start-Process -FilePath $LauncherTray
}
