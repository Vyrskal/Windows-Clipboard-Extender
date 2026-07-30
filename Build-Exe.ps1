<#
.SYNOPSIS
    Builds ClipboardUnlocker.ps1 into ClipboardUnlocker.exe (GUI, icon, requireAdmin manifest).
    Run on Windows in a normal PowerShell (admin rights are NOT needed to build).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Build-Exe.ps1
#>
[CmdletBinding()]
param(
    [string] $InputFile  = (Join-Path $PSScriptRoot 'ClipboardUnlocker.ps1'),
    [string] $OutputFile = (Join-Path $PSScriptRoot 'ClipboardUnlocker.exe'),
    [string] $IconFile   = (Join-Path $PSScriptRoot 'ClipboardUnlocker.ico'),
    [string] $Version    = '2.2.3.0'
)

$ErrorActionPreference = 'Stop'

Write-Host '== Clipboard Unlocker :: build ==' -ForegroundColor Cyan

if (-not (Test-Path $InputFile)) { throw "Not found: $InputFile" }

# 1) Make sure ps2exe is available
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installing ps2exe module (CurrentUser)...' -ForegroundColor Yellow
    try {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
    } catch {
        throw "Could not install ps2exe: $($_.Exception.Message). Install it manually: Install-Module ps2exe -Scope CurrentUser"
    }
}
Import-Module ps2exe -Force

# 2) Build parameters
$common = @{
    inputFile   = $InputFile
    outputFile  = $OutputFile
    noConsole   = $true      # GUI window, no console
    requireAdmin= $true      # manifest -> double-click prompts UAC right away
    title       = 'Clipboard Unlocker'
    description = 'Removes the Windows clipboard history limits (Win+V)'
    company     = 'Vyrskal'
    product     = 'Clipboard Unlocker'
    version     = $Version
    STA         = $true      # WinForms requires STA
}
if (Test-Path $IconFile) { $common['iconFile'] = $IconFile }
else { Write-Host "Icon $IconFile not found - building without it." -ForegroundColor Yellow }

# 3) Compile (Invoke-ps2exe in newer versions, ps2exe in older ones)
Write-Host "Compiling -> $OutputFile" -ForegroundColor Cyan
if (Get-Command Invoke-ps2exe -ErrorAction SilentlyContinue) {
    Invoke-ps2exe @common
} else {
    ps2exe @common
}

if (Test-Path $OutputFile) {
    $sz = [Math]::Round((Get-Item $OutputFile).Length / 1KB, 1)
    Write-Host "Done: $OutputFile ($sz KB)" -ForegroundColor Green
    Write-Host 'Ship this .exe. Double-click -> UAC -> APPLY.' -ForegroundColor Green
} else {
    throw 'Build produced no .exe - check the output above.'
}
