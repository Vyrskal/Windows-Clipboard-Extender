#Requires -RunAsAdministrator
#Requires -Version 5
<#
.SYNOPSIS
    Re-applies the clipboard patch at every logon via a scheduled task.

.DESCRIPTION
    Registers a Task Scheduler job (name 'ClipboardUnlocker') that runs the patcher
    silently and elevated (RunLevel Highest -> no UAC prompt) at each logon -- the same
    task the GUI (ClipboardUnlocker.exe) registers, so both entry points behave identically.

    The patch script is copied to a stable per-user location so the task keeps working
    even if this repo folder is later moved or deleted.
#>
$ErrorActionPreference = 'Stop'

$TaskName   = 'ClipboardUnlocker'
$installDir = Join-Path $env:LOCALAPPDATA 'ClipboardUnlocker'
$scriptDst  = Join-Path $installDir 'Patch-ClipboardHistory.ps1'
$src        = Join-Path $PSScriptRoot 'Patch-ClipboardHistory.ps1'

if (-not (Test-Path -LiteralPath $src)) {
    throw "Patch-ClipboardHistory.ps1 not found next to this script."
}

# Stable install location.
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -LiteralPath $src -Destination $scriptDst -Force

# Scheduled task: at logon, elevated, hidden window.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptDst`""
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5))

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Persistence installed as scheduled task '$TaskName'." -ForegroundColor Green
Write-Host "The patch will re-apply silently and elevated at every logon." -ForegroundColor Green
Write-Host "Installed to: $scriptDst" -ForegroundColor Cyan
Write-Host "To remove, run: .\Uninstall-Persistence.ps1" -ForegroundColor Cyan
