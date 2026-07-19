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

echo --- Starting Network Companion Components ---

:: Start AdGuard Home in background
if exist "%ADGUARD_EXE%" (
    echo [*] Starting AdGuard Home...
    start "AdGuard Home" /min "%ADGUARD_EXE%" -w "%PROJECT_ROOT%adguard"
) else (
    echo [!] AdGuard Home binary missing!
)

:: Start Dashboard
echo [*] Starting Dashboard...
start "Network Companion Dashboard" /min "%PYTHON_EXE%" dashboard\main.py

:: Start Scanner
echo [*] Starting Network Scanner...
start "Network Companion Scanner" /min "%PYTHON_EXE%" scanner\scanner.py

echo.
echo All components started!
echo Dashboard should be available at http://localhost:8000 (check dashboard\main.py for port)
echo.
pause
