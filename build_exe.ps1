# build_exe.ps1 — builds NetworkCompanion.exe from tray_launcher.py
# Run from project root: .\build_exe.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$PythonExe = Join-Path $ProjectRoot "python\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "[!] Bundled Python not found. Run setup.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Installing build dependencies..." -ForegroundColor Cyan
& $PythonExe -m pip install pystray pillow pyinstaller --quiet

Write-Host "[*] Building NetworkCompanion.exe..." -ForegroundColor Cyan
& $PythonExe -m PyInstaller `
    --onefile `
    --windowed `
    --name NetworkCompanion `
    "--distpath=$ProjectRoot" `
    "$ProjectRoot\tray_launcher.py"

# Clean up build artifacts
if (Test-Path "$ProjectRoot\build") { Remove-Item -Recurse -Force "$ProjectRoot\build" }
if (Test-Path "$ProjectRoot\NetworkCompanion.spec") { Remove-Item -Force "$ProjectRoot\NetworkCompanion.spec" }

if (Test-Path "$ProjectRoot\NetworkCompanion.exe") {
    $size = [math]::Round((Get-Item "$ProjectRoot\NetworkCompanion.exe").Length / 1MB, 1)
    Write-Host "[+] Done! NetworkCompanion.exe ($size MB) is ready." -ForegroundColor Green
} else {
    Write-Host "[!] Build failed — NetworkCompanion.exe not found." -ForegroundColor Red
    exit 1
}
