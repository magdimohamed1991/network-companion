@echo off
set PROJECT_ROOT=%~dp0
cd /d %PROJECT_ROOT%

:: Check if setup has been run
if not exist "%PROJECT_ROOT%python\python.exe" (
    echo [!] Bundled Python not found. Running setup first...
    powershell -NoProfile -ExecutionPolicy Bypass -File "setup.ps1"
)

:: Check if setup succeeded
if not exist "%PROJECT_ROOT%python\python.exe" (
    echo [!] Setup failed or was cancelled. Cannot start.
    pause
    exit /b 1
)

set PYTHON_EXE=%PROJECT_ROOT%python\python.exe
set ADGUARD_EXE=%PROJECT_ROOT%adguard\AdGuardHome.exe

echo --- Starting Network Companion ---

:: Start AdGuard Home in background
if exist "%ADGUARD_EXE%" (
    echo [*] Starting AdGuard Home...
    start "AdGuard Home" /min "%ADGUARD_EXE%" -w "%PROJECT_ROOT%adguard"
) else (
    echo [!] AdGuard Home binary missing - DNS features will be unavailable.
)

:: Start Dashboard (via uvicorn - required for FastAPI)
echo [*] Starting Dashboard...
start "Network Companion Dashboard" /min "%PYTHON_EXE%" -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8642

:: Start Scanner
echo [*] Starting Network Scanner...
start "Network Companion Scanner" /min "%PYTHON_EXE%" scanner\scanner.py

:: Start Notifier
echo [*] Starting Notifier...
start "Network Companion Notifier" /min "%PYTHON_EXE%" notifier.py

:: Start Anomaly Detector
echo [*] Starting Anomaly Detector...
start "Network Companion Anomaly Detector" /min "%PYTHON_EXE%" anomaly_detector.py

:: Start SNMP Monitor (will self-exit if snmp_enabled=false in config.json)
echo [*] Starting SNMP Monitor...
start "Network Companion SNMP Monitor" /min "%PYTHON_EXE%" snmp_monitor.py

echo.
echo All components started!
echo Dashboard: http://localhost:8642
echo.
pause
