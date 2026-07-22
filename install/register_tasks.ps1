<#
register_tasks.ps1

Sets up TWO Scheduled Tasks:
  - NetworkCompanion-ArpSpoofer  (AtLogOn, elevated/Highest): raw packet capture via
    Npcap requires Administrator rights — this is the only service that genuinely needs
    a Scheduled Task. Its elevation grant happens once at registration time, not at
    every launch, so there's no UAC pop-up when tray_launcher.py triggers it.
  - NetworkCompanion-Maintenance (daily at 4am): data retention rollup + pruning.

All other services (Scanner, Dashboard, Notifier, SNMPMonitor, AnomalyDetector) are
now started and managed directly by tray_launcher.py (NetworkCompanion.exe). Do NOT
re-add AtLogOn tasks for those — they would double-start alongside the tray launcher.

DEFAULT BEHAVIOR: ArpSpoofer runs when YOU log in (LogonType Interactive), using your
own Python environment.

WANT IT RUNNING EVEN WHEN LOGGED OUT? Open Task Scheduler (taskschd.msc), find
NetworkCompanion-ArpSpoofer, open Properties -> General -> check "Run whether user is
logged on or not". Windows will prompt for your password in its own trusted dialog.

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
# tray_launcher.py now starts Scanner, Dashboard, Notifier, SNMPMonitor, and AnomalyDetector
# directly — we only register ArpSpoofer (needs elevation) + Maintenance (daily schedule).
$TaskNames = @("NetworkCompanion-ArpSpoofer", "NetworkCompanion-Maintenance")

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

# Prefer the bundled Python (which has all required packages installed) over the system Python.
$BundledPython = Join-Path $ProjectRoot "python\python.exe"
if (Test-Path $BundledPython) {
    $PythonExe = $BundledPython
    Write-Host "Using bundled Python: $PythonExe"
} else {
    try {
        $PythonExe = (Get-Command python -ErrorAction Stop).Source
    } catch {
        Write-Host "Couldn't find python.exe on PATH. Install Python for Windows (not just inside WSL2)" -ForegroundColor Red
        Write-Host "and make sure 'Add python.exe to PATH' was checked during install, then re-run this script." -ForegroundColor Red
        exit 1
    }
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Write-Host "Using Python: $PythonExe"
Write-Host "Project root: $ProjectRoot"

$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$commonSettings = New-ScheduledTaskSettingsSet `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# --- ARP spoofer: needs admin (raw packet injection via Npcap) ---
# This is the only service that genuinely needs a Scheduled Task with "Highest privileges"
# since it requires administrator rights for raw packet capture. All other services are
# started directly by tray_launcher.py (NetworkCompanion.exe) now.
$spooferAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\scanner\arp_spoofer.py`"" -WorkingDirectory $ProjectRoot
$elevatedPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "NetworkCompanion-ArpSpoofer" -Action $spooferAction -Trigger $logonTrigger `
    -Settings $commonSettings -Principal $elevatedPrincipal -Description "Network Companion: opt-in ARP-spoof bandwidth capture (admin)" -Force | Out-Null
Write-Host "Registered NetworkCompanion-ArpSpoofer (elevated)"

# --- Maintenance: data retention (rollup + pruning). Runs once a day, not at every logon ---
$maintenanceAction = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ProjectRoot\maintenance.py`" --once" -WorkingDirectory $ProjectRoot
$dailyTrigger = New-ScheduledTaskTrigger -Daily -At 4am
Register-ScheduledTask -TaskName "NetworkCompanion-Maintenance" -Action $maintenanceAction -Trigger $dailyTrigger `
    -Settings $commonSettings -Description "Network Companion: daily data retention (rollup + log pruning)" -Force | Out-Null
Write-Host "Registered NetworkCompanion-Maintenance (daily at 4am)"

Write-Host "`nStarting tasks now (rather than waiting for next logon/schedule)..." -ForegroundColor Cyan
foreach ($name in $TaskNames) { Start-ScheduledTask -TaskName $name }

Start-Sleep -Seconds 3
Write-Host "`nStatus:"
Get-ScheduledTask -TaskName $TaskNames | Select-Object TaskName, State | Format-Table -AutoSize

Write-Host "`nNote: Scanner, Dashboard, Notifier, SNMP Monitor, and Anomaly Detector are now started" -ForegroundColor Yellow
Write-Host "by tray_launcher.py (NetworkCompanion.exe), not by Scheduled Tasks. Run NetworkCompanion.exe" -ForegroundColor Yellow
Write-Host "to start those services. Dashboard will be at http://localhost:8642." -ForegroundColor Yellow
