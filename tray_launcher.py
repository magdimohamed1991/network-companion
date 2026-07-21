"""
tray_launcher.py — Network Companion system tray launcher.

Double-click NetworkCompanion.exe (built from this script) to:
  • Start all services (AdGuard Home, Dashboard, Scanner, Notifier,
    Anomaly Detector, SNMP Monitor, ArpSpoofer) as hidden background processes.
  • Show a system tray icon with live service status in the tooltip.
  • Open the dashboard in the browser from the tray menu.
  • Stop all services cleanly from the tray menu.

Build command (run from project root with bundled Python):
    python\python.exe -m pip install pyinstaller pystray pillow
    python\python.exe -m PyInstaller --onefile --windowed --icon=icon.ico ^
        --name NetworkCompanion tray_launcher.py
"""

import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — resolve project root correctly both when run as .py and as .exe
# ---------------------------------------------------------------------------

# When frozen by PyInstaller, sys.executable is the .exe itself sitting in
# the project root. When run as a plain .py, __file__ gives us the script.
if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent
PYTHON_EXE = PROJECT_ROOT / "python" / "python.exe"
ADGUARD_EXE = PROJECT_ROOT / "adguard" / "AdGuardHome.exe"
CONFIG_PATH = PROJECT_ROOT / "config.json"

# ---------------------------------------------------------------------------
# Service definitions
# ---------------------------------------------------------------------------

SERVICES = [
    {
        "name": "Dashboard",
        "args": [str(PYTHON_EXE), "-m", "uvicorn", "dashboard.main:app",
                 "--host", "0.0.0.0", "--port", "8642"],
        "cwd": str(PROJECT_ROOT),
        "always_start": True,
    },
    {
        "name": "Scanner",
        "args": [str(PYTHON_EXE), str(PROJECT_ROOT / "scanner" / "scanner.py")],
        "cwd": str(PROJECT_ROOT),
        "always_start": True,
    },
    {
        "name": "Notifier",
        "args": [str(PYTHON_EXE), str(PROJECT_ROOT / "notifier.py")],
        "cwd": str(PROJECT_ROOT),
        "always_start": True,
    },
    {
        "name": "Anomaly Detector",
        "args": [str(PYTHON_EXE), str(PROJECT_ROOT / "anomaly_detector.py")],
        "cwd": str(PROJECT_ROOT),
        "always_start": True,
    },
    {
        "name": "SNMP Monitor",
        "args": [str(PYTHON_EXE), str(PROJECT_ROOT / "snmp_monitor.py")],
        "cwd": str(PROJECT_ROOT),
        "always_start": True,  # snmp_monitor exits itself if snmp_enabled=false
    },
    {
        "name": "AdGuard Home",
        "args": [str(ADGUARD_EXE), "-w", str(PROJECT_ROOT / "adguard")],
        "cwd": str(PROJECT_ROOT / "adguard"),
        "always_start": False,   # only started if the .exe exists
        "optional_binary": str(ADGUARD_EXE),
    },
    # ArpSpoofer requires Administrator privileges (raw packet capture via Npcap).
    # Rather than spawning it directly (which would either silently fail without elevation
    # or pop a UAC dialog on every launch), we delegate to the Scheduled Task that was
    # registered with "Highest privileges" by install/register_tasks.ps1.  Elevation was
    # granted once at task-registration time — no UAC prompt at runtime.
    #
    # "schtask_name" signals to _start_service / _stop_service to use
    #   schtasks /run /tn <name>   instead of subprocess.Popen
    #   schtasks /end /tn <name>   on stop
    # The watchdog skips this entry (Task Scheduler owns restart responsibility).
    {
        "name": "ArpSpoofer",
        "schtask_name": "NetworkCompanion-ArpSpoofer",
        "always_start": True,
    },
]

# ---------------------------------------------------------------------------
# Process manager
# ---------------------------------------------------------------------------

_processes: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()

CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _run_schtask(action: str, task_name: str) -> bool:
    """Invoke schtasks /run or /end for a named task.  Returns True on success."""
    try:
        result = subprocess.run(
            ["schtasks", f"/{action}", "/tn", task_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=CREATION_FLAGS,
            timeout=10,
        )
        if result.returncode != 0:
            err = result.stderr.decode(errors="replace").strip()
            print(f"[!] schtasks /{action} {task_name} failed (rc={result.returncode}): {err}")
            return False
        return True
    except Exception as e:
        print(f"[!] schtasks /{action} {task_name} error: {e}")
        return False


def _start_service(svc: dict) -> bool:
    """Start a single service. Returns True if launched successfully."""
    name = svc["name"]

    # Scheduled-task services (e.g. ArpSpoofer) are started via schtasks, not Popen.
    # Task Scheduler owns their lifecycle and restart policy — the watchdog skips them.
    if "schtask_name" in svc:
        task_name = svc["schtask_name"]
        ok = _run_schtask("run", task_name)
        if ok:
            print(f"[+] Started {name} via Scheduled Task '{task_name}'")
        return ok

    # Skip optional services whose binary doesn't exist or is inaccessible
    binary = svc.get("optional_binary")
    if binary:
        try:
            exists = Path(binary).exists()
        except PermissionError:
            exists = True  # file is locked/running — treat as present
        if not exists:
            print(f"[!] {name}: binary not found at {binary}, skipping.")
            return False

    # Don't double-start
    with _lock:
        proc = _processes.get(name)
        if proc and proc.poll() is None:
            return True  # already running

    try:
        proc = subprocess.Popen(
            svc["args"],
            cwd=svc["cwd"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATION_FLAGS,
        )
        with _lock:
            _processes[name] = proc
        print(f"[+] Started {name} (pid {proc.pid})")
        return True
    except Exception as e:
        print(f"[!] Failed to start {name}: {e}")
        return False


def start_all():
    for svc in SERVICES:
        _start_service(svc)


def stop_all():
    # Stop Scheduled Task services first
    for svc in SERVICES:
        if "schtask_name" in svc:
            task_name = svc["schtask_name"]
            print(f"[*] Stopping {svc['name']} via Scheduled Task '{task_name}'…")
            _run_schtask("end", task_name)

    with _lock:
        procs = dict(_processes)
    for name, proc in procs.items():
        if proc.poll() is None:
            print(f"[*] Stopping {name} (pid {proc.pid})…")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    with _lock:
        _processes.clear()


def _schtask_running(task_name: str) -> bool:
    """Returns True if the named Scheduled Task is currently in 'Running' state."""
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", task_name, "/fo", "csv", "/nh"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=CREATION_FLAGS,
            timeout=5,
        )
        # CSV output: "TaskName","Next Run Time","Status"
        # Status is "Running" when active, "Ready" when idle/stopped.
        output = result.stdout.decode(errors="replace")
        return "Running" in output
    except Exception:
        return False


def service_status() -> dict[str, bool]:
    """Returns {name: is_running} for every service."""
    status: dict[str, bool] = {}
    # Popen-managed services
    with _lock:
        for name, proc in _processes.items():
            status[name] = proc.poll() is None
    # Scheduled-task services
    for svc in SERVICES:
        if "schtask_name" in svc:
            status[svc["name"]] = _schtask_running(svc["schtask_name"])
    return status


# ---------------------------------------------------------------------------
# Watchdog — restart crashed services every 15 seconds
# ---------------------------------------------------------------------------

def _watchdog():
    while True:
        time.sleep(15)
        for svc in SERVICES:
            # Scheduled Task services are managed (and restarted) by Task Scheduler —
            # don't interfere with their lifecycle here.
            if "schtask_name" in svc:
                continue
            name = svc["name"]
            with _lock:
                proc = _processes.get(name)
            if proc is not None and proc.poll() is not None:
                # Process has exited — restart it
                print(f"[!] {name} exited (code {proc.returncode}), restarting…")
                _start_service(svc)


# ---------------------------------------------------------------------------
# Dashboard URL helper
# ---------------------------------------------------------------------------

def _dashboard_port() -> int:
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
        return int(cfg.get("dashboard_port", 8642))
    except Exception:
        return 8642


def open_dashboard():
    webbrowser.open(f"http://localhost:{_dashboard_port()}")


# ---------------------------------------------------------------------------
# Tray icon (pystray)
# ---------------------------------------------------------------------------

def _build_icon_image():
    """Create a simple coloured square as the tray icon (no .ico file required)."""
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Dark background circle
        draw.ellipse([4, 4, 60, 60], fill=(30, 30, 46, 255))
        # Teal wifi-like arc to hint at "network"
        draw.arc([12, 20, 52, 56], start=200, end=340, fill=(100, 220, 200, 255), width=5)
        draw.arc([20, 28, 44, 50], start=200, end=340, fill=(100, 220, 200, 200), width=4)
        draw.ellipse([29, 40, 35, 46], fill=(100, 220, 200, 255))
        return img
    except ImportError:
        # Pillow not available — return a plain 16×16 teal square
        try:
            from PIL import Image
            return Image.new("RGB", (16, 16), (100, 220, 200))
        except Exception:
            return None


def _tooltip_text() -> str:
    status = service_status()
    lines = ["Network Companion"]
    for svc in SERVICES:
        name = svc["name"]
        running = status.get(name, False)
        dot = "●" if running else "○"
        lines.append(f"  {dot} {name}")
    return "\n".join(lines)


def _make_menu(icon):
    import pystray

    def open_action(icon, item):
        open_dashboard()

    def stop_action(icon, item):
        icon.notify("Stopping all services…", "Network Companion")
        stop_all()
        icon.stop()

    def status_action(icon, item):
        status = service_status()
        lines = []
        for svc in SERVICES:
            name = svc["name"]
            state = "running" if status.get(name) else "stopped"
            lines.append(f"{name}: {state}")
        icon.notify("\n".join(lines), "Service Status")

    return pystray.Menu(
        pystray.MenuItem("Open Dashboard", open_action, default=True),
        pystray.MenuItem("Service Status", status_action),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Stop All & Exit", stop_action),
    )


def run_tray():
    try:
        import pystray
    except ImportError:
        # pystray not available — run headlessly, just keep the process alive
        print("[i] pystray not installed — running without tray icon. Close this window to stop.")
        print(f"[i] Dashboard: http://localhost:{_dashboard_port()}")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            stop_all()
        return

    img = _build_icon_image()
    if img is None:
        from PIL import Image
        img = Image.new("RGB", (16, 16), (100, 220, 200))

    icon = pystray.Icon(
        name="NetworkCompanion",
        icon=img,
        title="Network Companion",
        menu=_make_menu(None),  # placeholder, rebuilt below
    )
    icon.menu = _make_menu(icon)

    # Update tooltip every 10s
    def _update_tooltip():
        while icon.visible if hasattr(icon, "visible") else True:
            try:
                icon.title = _tooltip_text()
            except Exception:
                pass
            time.sleep(10)

    threading.Thread(target=_update_tooltip, daemon=True).start()

    # Open browser after a short delay so the dashboard has time to start
    threading.Timer(3.0, open_dashboard).start()

    icon.run()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Ensure we're running from project root
    os.chdir(PROJECT_ROOT)

    # Check bundled Python exists
    if not PYTHON_EXE.exists():
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Bundled Python not found at:\n{PYTHON_EXE}\n\nRun setup.ps1 first.",
            "Network Companion",
            0x10,  # MB_ICONERROR
        )
        sys.exit(1)

    print("[i] Starting Network Companion…")
    try:
        start_all()
    except Exception as e:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Failed to start services:\n{e}\n\nCheck that no other instance is already running.",
            "Network Companion",
            0x10,
        )
        sys.exit(1)

    # Start watchdog in background
    threading.Thread(target=_watchdog, daemon=True).start()

    # Run tray (blocks until user clicks Stop All & Exit)
    run_tray()

    # Cleanup on exit
    stop_all()
    print("[i] Goodbye.")
