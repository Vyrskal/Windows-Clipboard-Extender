#Requires -RunAsAdministrator
#Requires -Version 5
<#
.SYNOPSIS
    Removes the logon scheduled task installed by Install-Persistence.ps1
    (and any leftover legacy Startup-folder / C:\Tools launcher from older versions).
#>
$ErrorActionPreference = 'Stop'

$TaskName   = 'ClipboardHistoryPatch'
$installDir = Join-Path $env:LOCALAPPDATA 'ClipboardUnlocker'
$scriptDst  = Join-Path $installDir 'Patch-ClipboardHistory.ps1'
$removed    = $false

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
    $removed = $true
}

if (Test-Path -LiteralPath $scriptDst) {
    Remove-Item -LiteralPath $scriptDst -Force
    Write-Host "Removed installed patch script." -ForegroundColor Green
    $removed = $true
}

# Legacy cleanup (old Startup-folder / C:\Tools method).
$legacyStartup = Join-Path ([Environment]::GetFolderPath('Startup')) 'ClipboardPatchLauncher.vbs'
if (Test-Path $legacyStartup) {
    Remove-Item $legacyStartup -Force
    Write-Host "Removed legacy Startup launcher." -ForegroundColor Green
    $removed = $true
}
foreach ($f in 'ClipboardPatchLauncher.vbs', 'ClipboardPatch.ps1') {
    $p = Join-Path 'C:\Tools' $f
    if (Test-Path $p) { Remove-Item $p -Force; $removed = $true }
}

if ($removed) {
    Write-Host "Uninstall complete. The patch will no longer apply at logon." -ForegroundColor Green
} else {
    Write-Host "Nothing to uninstall." -ForegroundColor Yellow
}
