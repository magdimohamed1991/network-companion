# fix_spoofer_task.ps1 — Run as Administrator
# Fixes the NetworkCompanion-ArpSpoofer scheduled task to use the bundled Python
# instead of whatever system Python was on PATH when register_tasks.ps1 was first run.

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Run this script as Administrator (right-click -> Run as Administrator)." -ForegroundColor Red
    pause
    exit 1
}

$ProjectRoot = $PSScriptRoot
$BundledPython = Join-Path $ProjectRoot "python\python.exe"
$SpooferScript = Join-Path $ProjectRoot "scanner\arp_spoofer.py"

if (-not (Test-Path $BundledPython)) {
    Write-Host "ERROR: Bundled Python not found at $BundledPython" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "Updating NetworkCompanion-ArpSpoofer to use: $BundledPython" -ForegroundColor Cyan

Unregister-ScheduledTask -TaskName "NetworkCompanion-ArpSpoofer" -Confirm:$false -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute $BundledPython -Argument "`"$SpooferScript`"" -WorkingDirectory $ProjectRoot
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
               -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries `
               -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName "NetworkCompanion-ArpSpoofer" `
    -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description "Network Companion: opt-in ARP-spoof bandwidth capture (admin)" -Force | Out-Null

Write-Host "Task updated. Starting it now..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName "NetworkCompanion-ArpSpoofer"
Start-Sleep -Seconds 3

$task = Get-ScheduledTask -TaskName "NetworkCompanion-ArpSpoofer"
Write-Host "Status: $($task.State)" -ForegroundColor Green
schtasks /query /tn "NetworkCompanion-ArpSpoofer" /fo LIST /v | Select-String "Task To Run|Last Result|Status"

Write-Host "`nDone. The spoofer should now start collecting bandwidth data." -ForegroundColor Green
pause
