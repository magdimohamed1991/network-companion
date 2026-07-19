# Network Companion - Zero-Setup Package Setup Script
# This script automates prerequisites and handles Windows Security exclusions

$ErrorActionPreference = "Stop"
$ProjectRoot = Get-Location
$InstallDir = Join-Path $ProjectRoot "install"

# --- Elevation Check ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "--- Network Companion Setup ---" -ForegroundColor Cyan

# --- Windows Security Bypass (Exclusions) ---
Write-Host "Adding project directory to Windows Defender exclusions..." -ForegroundColor Gray
Add-MpPreference -ExclusionPath $ProjectRoot -ErrorAction SilentlyContinue

# --- Npcap Check & Install ---
Write-Host "Checking for Npcap..." -ForegroundColor Gray
if (-not (Get-Service "npcap" -ErrorAction SilentlyContinue)) {
    Write-Host "Npcap not found. Installing..." -ForegroundColor Yellow
    $NpcapInstaller = Join-Path $InstallDir "npcap-installer.exe"
    # Silent install flags for Npcap
    Start-Process -FilePath $NpcapInstaller -ArgumentList "/S /winpcap_mode=yes" -Wait
} else {
    Write-Host "Npcap is already installed." -ForegroundColor Green
}

# --- Python Embeddable Setup ---
$PythonDir = Join-Path $ProjectRoot "python"
if (-not (Test-Path $PythonDir)) {
    Write-Host "Setting up bundled Python environment..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $PythonDir | Out-Null
    Expand-Archive -Path (Join-Path $InstallDir "python-embed.zip") -DestinationPath $PythonDir
    
    # Enable pip
    $PythonExe = Join-Path $PythonDir "python.exe"
    $GetPip = Join-Path $InstallDir "get-pip.py"
    
    # Modify python311._pth to enable site-packages
    $PthFile = Get-ChildItem -Path $PythonDir -Filter "*._pth" | Select-Object -First 1
    if ($PthFile) {
        (Get-Content $PthFile.FullName) -replace "#import site", "import site" | Set-Content $PthFile.FullName
    }
    
    Write-Host "Installing pip..." -ForegroundColor Gray
    Start-Process -FilePath $PythonExe -ArgumentList $GetPip -Wait
    
    Write-Host "Installing Python dependencies..." -ForegroundColor Gray
    $Requirements = Join-Path $ProjectRoot "requirements.txt"
    Start-Process -FilePath $PythonExe -ArgumentList "-m pip install -r `"$Requirements`"" -Wait
} else {
    Write-Host "Bundled Python environment found." -ForegroundColor Green
}

Write-Host "--- Setup Complete! ---" -ForegroundColor Green
Write-Host "You can now use 'launcher.bat' to start the application."
