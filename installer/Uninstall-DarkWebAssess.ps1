<#
.SYNOPSIS
    Uninstall the DarkWebAssess Windows bundle.

.DESCRIPTION
    Removes the install directory, Start Menu folder, and Desktop shortcut.
    The data directory (%APPDATA%\DarkWebAssess) is preserved by default — you
    keep your DB, watchlist edits, and logs. Pass -RemoveData to wipe it.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\DarkWebAssess"),
    [string]$DataDir    = (Join-Path $env:APPDATA "DarkWebAssess"),
    [switch]$RemoveData
)

$ErrorActionPreference = "Continue"

function Write-Step($msg) { Write-Host "[uninstall] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[uninstall] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "[uninstall] WARN $msg" -ForegroundColor Yellow }

# --- 1. Stop any running tray / dashboard -----------------------------------
Write-Step "Stopping any running mini-threat-intel.exe ..."
Get-Process -Name "mini-threat-intel" -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.Kill(); $_.WaitForExit(3000) } catch { Write-Warn2 "could not kill PID $($_.Id): $_" }
}

# --- 2. Remove shortcuts ----------------------------------------------------
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\DarkWebAssess"
if (Test-Path $StartMenu) {
    Write-Step "Removing Start Menu folder ..."
    Remove-Item -Recurse -Force $StartMenu
}
$Desktop = [Environment]::GetFolderPath("Desktop")
$DesktopLnk = Join-Path $Desktop "DarkWebAssess.lnk"
if (Test-Path $DesktopLnk) {
    Write-Step "Removing Desktop shortcut ..."
    Remove-Item -Force $DesktopLnk
}

# --- 3. Remove install directory --------------------------------------------
if (Test-Path $InstallDir) {
    Write-Step "Removing install directory: $InstallDir"
    try {
        Remove-Item -Recurse -Force $InstallDir
    } catch {
        Write-Warn2 "could not remove $InstallDir cleanly: $_"
    }
}

# --- 4. Optionally remove data ---------------------------------------------
if ($RemoveData -and (Test-Path $DataDir)) {
    Write-Step "Removing data directory: $DataDir"
    Remove-Item -Recurse -Force $DataDir
} elseif (Test-Path $DataDir) {
    Write-Host "[uninstall] Data directory preserved at: $DataDir" -ForegroundColor Yellow
    Write-Host "[uninstall] Pass -RemoveData to delete it as well." -ForegroundColor Yellow
}

Write-Ok "Uninstall complete."
