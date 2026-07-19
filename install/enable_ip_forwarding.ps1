<#
enable_ip_forwarding.ps1

WHY THIS EXISTS
    ARP spoofing only redirects traffic to flow THROUGH this machine — by itself that's
    just a denial of service, since Windows normally drops packets that arrive but aren't
    addressed to it at the IP layer. This script flips the one registry setting that tells
    Windows "also forward packets on to their real destination," so the ARP-spoofed
    devices keep working normally while arp_spoofer.py measures their traffic.

    This is a one-time setup step, separate from arp_spoofer.py itself, because it needs
    a REBOOT to take effect — Windows only reads IPEnableRouter at boot.

USAGE
    Right-click PowerShell -> Run as Administrator, then:
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\enable_ip_forwarding.ps1
    Reboot when it tells you to.

    To undo later: re-run with -Disable
#>

param(
    [switch]$Disable
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This must be run as Administrator. Right-click PowerShell -> Run as Administrator, then re-run this script." -ForegroundColor Red
    exit 1
}

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$value = if ($Disable) { 0 } else { 1 }

Set-ItemProperty -Path $regPath -Name "IPEnableRouter" -Value $value -Type DWord

if ($Disable) {
    Write-Host "IP forwarding disabled (IPEnableRouter=0). Reboot for this to take effect." -ForegroundColor Yellow
} else {
    Write-Host "IP forwarding enabled (IPEnableRouter=1). This machine will now route traffic" -ForegroundColor Green
    Write-Host "for any device that ARP-spoofs through it once arp_spoofer.py arms one." -ForegroundColor Green
    Write-Host ""
    Write-Host "REBOOT REQUIRED before arp_spoofer.py will actually forward traffic correctly." -ForegroundColor Yellow
}
