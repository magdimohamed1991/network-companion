<#
register_tasks.ps1

Sets up five Scheduled Tasks so scanner.py, arp_spoofer.py, the dashboard, notifier, and
daily maintenance start automatically and restart themselves if they crash — this is
what makes "always live" actually true day to day, without needing a third-party service
wrapper. The first four start at login; maintenance runs once daily at 4am regardless.

DEFAULT BEHAVIOR: tasks run when YOU log in (LogonType Interactive), using your own
Python environment, so anything you `pip install`ed for your user is visible to them.

WANT THEM RUNNING EVEN WHEN LOGGED OUT? Open Task Scheduler (taskschd.msc), find the
login-triggered "NetworkCompanion-*" tasks (Scanner, ArpSpoofer, Dashboard, Notifier —
Maintenance already runs on its own daily schedule regardless of login), open Properties
-> General -> check "Run whether user is logged on or not". Windows will prompt for your
password right there in its own trusted dialog — deliberately not handled in this
script, so your password is never written to a file.

USAGE
    Right-click PowerShell -> Run as Administrator (needed for the ArpSpoofer task's
    "Highest privileges" setting), then:
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\register_tasks.ps1

    To remove everything later:
        .\register_tasks.ps1 -Unregister
#>

param(
    [switch]$Unregister
)

$ErrorActionPreference = "Stop"
$TaskNames = @("NetworkCompanion-Scanner", "NetworkCompanion-ArpSpoofer", "NetworkCompanion-Dashboard", "NetworkCompanion-Maintenance", "NetworkCompanion-Notifier", "NetworkCompanion-SNMPMonitor")

if ($Unregister) {
    foreach ($name in $TaskNames) {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Host "Removed $name"
        }
    }
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Run as Administrator (needed to register the ArpSpoofer task with highest privileges)." -ForegroundColor Red
    exit 1
}

try {
    $PythonExe = (Get-Command python -ErrorAction Stop).Source
} catch {
    Write-Host "Couldn't find python.exe on PATH. Install Python for Windows (not just inside WSL2)" -ForegroundColor Red
    Write-Host "and make sure 'Add python.exe to PATH' was checked during install, then re-run this script." -ForegroundColor Red
    exit 1
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Write-Host "Using Python: $PythonExe"
Write-Host "Project root: $ProjectRoot"

$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$commonSettings = New-ScheduledTaskSettingsSet `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# --- Scanner: passive discovery, no elevated rights needed ---
$scannerAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\scanner\scanner.py`"" -WorkingDirectory $ProjectRoot
Register-ScheduledTask -TaskName "NetworkCompanion-Scanner" -Action $scannerAction -Trigger $logonTrigger `
    -Settings $commonSettings -Description "Network Companion: passive ping-sweep device discovery" -Force | Out-Null
Write-Host "Registered NetworkCompanion-Scanner"

# --- ARP spoofer: needs admin (raw packet injection via Npcap) ---
$spooferAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\scanner\arp_spoofer.py`"" -WorkingDirectory $ProjectRoot
$elevatedPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "NetworkCompanion-ArpSpoofer" -Action $spooferAction -Trigger $logonTrigger `
    -Settings $commonSettings -Principal $elevatedPrincipal -Description "Network Companion: opt-in ARP-spoof bandwidth capture (admin)" -Force | Out-Null
Write-Host "Registered NetworkCompanion-ArpSpoofer (elevated)"

# --- Dashboard: bound to 0.0.0.0 so you can check it from your phone on the same LAN ---
$dashboardAction = New-ScheduledTaskAction -Execute $PythonExe `
    -Argument "-m uvicorn dashboard.main:app --host 0.0.0.0 --port 8642" -WorkingDirectory $ProjectRoot
Register-ScheduledTask -TaskName "NetworkCompanion-Dashboard" -Action $dashboardAction -Trigger $logonTrigger `
    -Settings $commonSettings -Description "Network Companion: web dashboard on port 8642" -Force | Out-Null
Write-Host "Registered NetworkCompanion-Dashboard"

# --- Maintenance: data retention (rollup + pruning). Runs once a day, not at every logon ---
$maintenanceAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\maintenance.py`" --once" -WorkingDirectory $ProjectRoot
$dailyTrigger = New-ScheduledTaskTrigger -Daily -At 4am
Register-ScheduledTask -TaskName "NetworkCompanion-Maintenance" -Action $maintenanceAction -Trigger $dailyTrigger `
    -Settings $commonSettings -Description "Network Companion: daily data retention (rollup + log pruning)" -Force | Out-Null
Write-Host "Registered NetworkCompanion-Maintenance (daily at 4am)"

# --- Notifier: watches for new-device/watchdog events and quota crossings ---
$notifierAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\notifier.py`"" -WorkingDirectory $ProjectRoot
Register-ScheduledTask -TaskName "NetworkCompanion-Notifier" -Action $notifierAction -Trigger $logonTrigger `
    -Settings $commonSettings -Description "Network Companion: notifications (Windows toast / Telegram)" -Force | Out-Null
Write-Host "Registered NetworkCompanion-Notifier"

# --- SNMP Monitor: router-level bandwidth monitoring ---
$snmpAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\snmp_monitor.py`"" -WorkingDirectory $ProjectRoot
Register-ScheduledTask -TaskName "NetworkCompanion-SNMPMonitor" -Action $snmpAction -Trigger $logonTrigger `
    -Settings $commonSettings -Description "Network Companion: router SNMP bandwidth monitoring" -Force | Out-Null
Write-Host "Registered NetworkCompanion-SNMPMonitor"

Write-Host "`nStarting all six now (rather than waiting for next logon/schedule)..." -ForegroundColor Cyan
foreach ($name in $TaskNames) { Start-ScheduledTask -TaskName $name }

Start-Sleep -Seconds 3
Write-Host "`nStatus:"
Get-ScheduledTask -TaskName $TaskNames | Select-Object TaskName, State | Format-Table -AutoSize

Write-Host "Dashboard should now be reachable at http://localhost:8642 (and from other devices" -ForegroundColor Green
Write-Host "on your network at http://<this-PC-IP>:8642)." -ForegroundColor Green
