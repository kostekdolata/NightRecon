param(
    [switch]$Elevated
)

$ErrorActionPreference = "Stop"
$AppDir = Split-Path -Parent $PSCommandPath
$WorkingDir = Join-Path $env:LOCALAPPDATA "NightRecon\RedNight"
$PowerShellExe = Join-Path $PSHOME "powershell.exe"

if (-not $Elevated) {
    $arguments = "-NoProfile -NoExit -File `"$PSCommandPath`" -Elevated"
    Start-Process -FilePath $PowerShellExe -Verb RunAs -ArgumentList $arguments -WorkingDirectory $WorkingDir
    exit
}

$env:PATH = "$AppDir;$env:PATH"
Set-Location $WorkingDir
& (Join-Path $AppDir "RedNight.exe") --help

Write-Host ""
Write-Host "Red Night terminal ready."
Write-Host "Use: RedNight.exe <command> [options]"
Write-Host "Working directory: $WorkingDir"
