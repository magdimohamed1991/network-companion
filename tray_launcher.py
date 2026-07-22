"""
tray_launcher.py — Network Companion system tray launcher.

Double-click NetworkCompanion.exe (built from this script) to:
  • Validate the environment (Python, Npcap, AdGuard binary) and fix what it can silently.
  • Download AdGuard Home automatically if the binary is missing.
  • Start all services (AdGuard Home, Dashboard, Scanner, Notifier,
    Anomaly Detector, SNMP Monitor, ArpSpoofer) as hidden background processes.
  • ArpSpoofer: tries the Scheduled Task first (no UAC pop-up). If the task doesn't
    exist, auto-registers it (requires a one-time UAC prompt), then starts it.
    Falls back to a direct elevated Popen if Task Scheduler fails for any reason.
  • Show a system tray icon with live service status in the tooltip.
  • Open the dashboard in the browser from the tray menu.
  • Stop all services cleanly from the tray menu.

Build command (run from project root with bundled Python):
    python\\python.exe -m pip install pyinstaller pystray pillow
    python\\python.exe -m PyInstaller --onefile --windowed --name NetworkCompanion ^
        tray_launcher.py
"""

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — resolve project root correctly both when run as .py and as .exe
# ---------------------------------------------------------------------------

if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent

PYTHON_EXE  = PROJECT_ROOT / "python" / "python.exe"
ADGUARD_DIR = PROJECT_ROOT / "adguard"
ADGUARD_EXE = ADGUARD_DIR  / "AdGuardHome.exe"
CONFIG_PATH = PROJECT_ROOT / "config.json"

# ---------------------------------------------------------------------------
# Logging — everything goes to a log file (exe is --windowed, no console).
# ---------------------------------------------------------------------------

LOG_PATH = PROJECT_ROOT / "tray_launcher.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8")],
)
_log = logging.getLogger("tray_launcher")


def _print(msg: str):
    print(msg)
    _log.info(msg)


# ---------------------------------------------------------------------------
# Helper — show a native Windows message box (works even from a --windowed exe)
# ---------------------------------------------------------------------------

def _msgbox(title: str, text: str, style: int = 0x40):
    """MB_OK (0) + MB_ICONINFORMATION (0x40).  Use style=0x10 for error icon."""
    ctypes.windll.user32.MessageBoxW(0, text, title, style)


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AdGuard Home — download if missing
# ---------------------------------------------------------------------------

# Official GitHub release URL for AdGuard Home Windows x64
_AGH_RELEASE_URL = (
    "https://github.com/AdguardTeam/AdGuardHome/releases/latest/download/"
    "AdGuardHome_windows_amd64.zip"
)
_AGH_ZIP = ADGUARD_DIR / "AdGuardHome_windows_amd64.zip"


def _download_adguard() -> bool:
    """Download and extract AdGuard Home binary into the adguard/ folder.
    Shows a progress indicator via the log; returns True on success."""
    _print("[*] AdGuard Home binary not found — downloading from GitHub...")
    try:
        ADGUARD_DIR.mkdir(parents=True, exist_ok=True)

        def _report(block_count, block_size, total):
            downloaded = block_count * block_size
            if total > 0:
                pct = min(100, downloaded * 100 // total)
                if block_count % 50 == 0:
                    _print(f"    Downloading AdGuard Home... {pct}%")

        urllib.request.urlretrieve(_AGH_RELEASE_URL, _AGH_ZIP, reporthook=_report)
        _print("[*] Download complete. Extracting...")

        import zipfile
        with zipfile.ZipFile(_AGH_ZIP, "r") as zf:
            # The zip contains a single folder 'AdGuardHome/' with the exe inside
            for member in zf.namelist():
                if member.endswith("AdGuardHome.exe"):
                    data = zf.read(member)
                    ADGUARD_EXE.write_bytes(data)
                    _print(f"[+] Extracted AdGuardHome.exe ({len(data) // 1024} KB)")
                    break
            else:
                _print("[!] AdGuardHome.exe not found inside the downloaded zip.")
                return False

        _AGH_ZIP.unlink(missing_ok=True)

        if ADGUARD_EXE.exists():
            _print("[+] AdGuard Home is ready.")
            return True
        return False

    except Exception as e:
        _print(f"[!] Failed to download AdGuard Home: {e}")
        return False


# ---------------------------------------------------------------------------
# Npcap — silent install from bundled installer
# ---------------------------------------------------------------------------

NPCAP_INSTALLER = PROJECT_ROOT / "install" / "npcap-installer.exe"


def _install_npcap() -> bool:
    """
    Install Npcap from the bundled installer.
    Silent mode (/S) is OEM-only, so we run the GUI installer elevated and
    wait for the user to complete it, then verify the npcap service appeared.
    Returns True once the npcap service is detected (up to 3 min wait).
    """
    if not NPCAP_INSTALLER.exists():
        _print(f"[!] Npcap installer not found at {NPCAP_INSTALLER}")
        return False

    _print(f"[*] Launching Npcap installer from {NPCAP_INSTALLER} ...")

    # Show a prompt so the user knows what's about to happen
    ctypes.windll.user32.MessageBoxW(
        0,
        "Npcap is required for bandwidth tracking.\n\n"
        "The Npcap installer will open now.\n"
        "Please complete the installation, then Network Companion will continue automatically.",
        "Network Companion — Npcap Required",
        0x40,  # MB_ICONINFORMATION
    )

    def _npcap_running() -> bool:
        try:
            r = subprocess.run(
                ["sc", "query", "npcap"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return r.returncode == 0
        except Exception:
            return False

    try:
        if _is_admin():
            # Already elevated — run directly and wait
            subprocess.run(
                [str(NPCAP_INSTALLER)],
                timeout=300,
            )
        else:
            # Need elevation — ShellExecute runas, then poll for the service
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas",
                str(NPCAP_INSTALLER),
                "",
                str(PROJECT_ROOT),
                1,   # SW_SHOWNORMAL — installer needs to be visible
            )
            if ret <= 32:
                _print(f"[!] ShellExecute for Npcap installer returned {ret} — UAC denied?")
                return False
            # Wait up to 3 minutes for the npcap service to appear
            _print("[*] Waiting for Npcap installation to complete...")
            for _ in range(180):
                time.sleep(1)
                if _npcap_running():
                    break

    except Exception as e:
        _print(f"[!] Npcap install failed: {e}")
        return False

    if _npcap_running():
        _print("[+] Npcap installed successfully.")
        return True
    else:
        _print("[!] Npcap installer ran but service was not detected.")
        return False


# ---------------------------------------------------------------------------
# Environment validation — runs before any service is started
# ---------------------------------------------------------------------------

def _validate_environment() -> list[str]:
    """
    Check all prerequisites.  Returns a list of warning strings for things that
    were skipped or need attention; an empty list means everything is fine.
    Non-fatal issues are logged; fatal ones raise SystemExit after showing a dialog.
    """
    warnings: list[str] = []

    # 0. Add Windows Defender exclusion for the project folder so binaries aren't quarantined
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden",
             "-Command", f"Add-MpPreference -ExclusionPath '{PROJECT_ROOT}' -ErrorAction SilentlyContinue"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=15,
        )
    except Exception:
        pass   # non-fatal — Defender exclusion is best-effort

    # 1. Bundled Python (fatal — nothing can start without it)
    if not PYTHON_EXE.exists():
        msg = (
            f"Bundled Python not found at:\n{PYTHON_EXE}\n\n"
            "Run setup.ps1 first, then try again."
        )
        _print(f"[!] FATAL: {msg}")
        _msgbox("Network Companion — Setup required", msg, 0x10)
        sys.exit(1)

    # 2. AdGuard Home binary (non-fatal — download it silently)
    # PermissionError means the file exists but is locked (already running) — treat as present.
    try:
        adguard_missing = not ADGUARD_EXE.exists()
    except PermissionError:
        adguard_missing = False  # locked = running = present

    if adguard_missing:
        _print("[!] AdGuard Home binary missing.")
        ok = _download_adguard()
        if not ok:
            warnings.append(
                "AdGuard Home could not be downloaded.\n"
                "DNS filtering features will be unavailable.\n"
                "Place AdGuardHome.exe in the 'adguard\\' folder to enable it."
            )

    # 3. Npcap — install silently if missing (bundled installer in install\npcap-installer.exe)
    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        npcap_ok = result.returncode == 0
    except Exception:
        npcap_ok = False

    if not npcap_ok:
        _print("[!] Npcap not found — attempting silent install...")
        npcap_ok = _install_npcap()
        if not npcap_ok:
            warnings.append(
                "Npcap installation was not completed or could not be verified.\n"
                "Bandwidth tracking and ARP-spoof relay will be unavailable.\n"
                "Re-run NetworkCompanion.exe to try again."
            )

    return warnings


# ---------------------------------------------------------------------------
# ArpSpoofer — Scheduled Task helpers
# ---------------------------------------------------------------------------

_SCHTASK_SPOOFER = "NetworkCompanion-ArpSpoofer"


def _schtask_exists(task_name: str) -> bool:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", task_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _schtask_running(task_name: str) -> bool:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", task_name, "/fo", "csv", "/nh"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=5,
        )
        return "Running" in result.stdout.decode(errors="replace")
    except Exception:
        return False


def _run_schtask(action: str, task_name: str) -> bool:
    """schtasks /run or /end.  Returns True on success."""
    try:
        result = subprocess.run(
            ["schtasks", f"/{action}", "/tn", task_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=10,
        )
        if result.returncode != 0:
            err = result.stderr.decode(errors="replace").strip()
            _print(f"[!] schtasks /{action} {task_name} failed (rc={result.returncode}): {err}")
            return False
        return True
    except Exception as e:
        _print(f"[!] schtasks /{action} {task_name} error: {e}")
        return False


def _register_spoofer_task() -> bool:
    """
    Register the NetworkCompanion-ArpSpoofer Scheduled Task with Highest privileges.
    Requires admin rights.  If we're not admin, re-launch ourselves elevated via ShellExecute
    to run the PowerShell registration script, then wait for it.
    Returns True if the task now exists.
    """
    register_ps1 = PROJECT_ROOT / "install" / "register_tasks.ps1"
    if not register_ps1.exists():
        _print(f"[!] register_tasks.ps1 not found at {register_ps1}")
        return False

    _print("[*] Registering ArpSpoofer Scheduled Task (requires admin)...")

    if _is_admin():
        # Already elevated — run directly
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(register_ps1),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=30,
                cwd=str(PROJECT_ROOT),
            )
            _print(result.stdout.decode(errors="replace"))
            if result.returncode != 0:
                _print(f"[!] register_tasks.ps1 failed: {result.stderr.decode(errors='replace')}")
                return False
        except Exception as e:
            _print(f"[!] Failed to run register_tasks.ps1: {e}")
            return False
    else:
        # Ask Windows to elevate a powershell that runs only the registration
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe",
                f'-NoProfile -ExecutionPolicy Bypass -File "{register_ps1}"',
                str(PROJECT_ROOT),
                1,  # SW_SHOWNORMAL — must be visible so user can confirm UAC
            )
            if ret <= 32:
                _print(f"[!] ShellExecute elevation returned {ret} — UAC was denied or failed.")
                return False
            # Wait up to 20s for the task to appear
            for _ in range(20):
                time.sleep(1)
                if _schtask_exists(_SCHTASK_SPOOFER):
                    _print("[+] ArpSpoofer Scheduled Task registered successfully.")
                    return True
            _print("[!] Timed out waiting for task registration.")
            return False
        except Exception as e:
            _print(f"[!] Failed to elevate for task registration: {e}")
            return False

    return _schtask_exists(_SCHTASK_SPOOFER)


def _start_spoofer_direct() -> "subprocess.Popen | None":
    """
    Last-resort fallback: start arp_spoofer.py directly with ShellExecute 'runas'
    (triggers a UAC prompt) so it gets the admin rights Npcap requires.
    Returns None — we can't get a Popen handle from ShellExecute, so the process
    is tracked separately via _spoofer_pid_file.
    """
    _print("[*] Falling back to direct elevated launch for ArpSpoofer...")
    spoofer_py = PROJECT_ROOT / "scanner" / "arp_spoofer.py"
    if not spoofer_py.exists():
        _print(f"[!] arp_spoofer.py not found at {spoofer_py}")
        return None
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(PYTHON_EXE),
            f'"{spoofer_py}"',
            str(PROJECT_ROOT),
            0,  # SW_HIDE
        )
        if ret > 32:
            _print("[+] ArpSpoofer launched (elevated, hidden).")
        else:
            _print(f"[!] ShellExecute for ArpSpoofer returned {ret} — UAC may have been denied.")
    except Exception as e:
        _print(f"[!] Failed to launch ArpSpoofer directly: {e}")
    return None


# ---------------------------------------------------------------------------
# Service definitions
# ---------------------------------------------------------------------------

SERVICES = [
    {
        "name": "Dashboard",
        "args": [
            str(PYTHON_EXE), "-m", "uvicorn", "dashboard.main:app",
            "--host", "0.0.0.0", "--port", "8642",
        ],
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
        "args": [str(ADGUARD_EXE), "-w", str(ADGUARD_DIR)],
        "cwd": str(ADGUARD_DIR),
        "always_start": False,
        "optional_binary": str(ADGUARD_EXE),
    },
    # ArpSpoofer needs Administrator rights (raw packet capture via Npcap).
    # Strategy (tried in order):
    #   1. Existing Scheduled Task  → schtasks /run  (no UAC pop-up, preferred)
    #   2. Task doesn't exist       → auto-register via register_tasks.ps1 (one UAC prompt)
    #   3. Fallback                 → ShellExecute runas python arp_spoofer.py (UAC each time)
    # "schtask_name" signals to _start_service / _stop_service to use this logic.
    {
        "name": "ArpSpoofer",
        "schtask_name": _SCHTASK_SPOOFER,
        "always_start": True,
    },
]

# ---------------------------------------------------------------------------
# Process manager
# ---------------------------------------------------------------------------

_processes: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()

# All child processes are started with CREATE_NO_WINDOW — no console ever appears.
CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _start_service(svc: dict) -> bool:
    """Start a single service.  Returns True if launched (or already running)."""
    name = svc["name"]

    # ---- ArpSpoofer: Scheduled Task or elevated fallback ----
    if "schtask_name" in svc:
        task_name = svc["schtask_name"]

        if _schtask_exists(task_name):
            ok = _run_schtask("run", task_name)
            if ok:
                _print(f"[+] Started {name} via Scheduled Task '{task_name}'")
            return ok

        # Task doesn't exist — try to register it first
        _print(f"[i] Scheduled Task '{task_name}' not found — attempting auto-registration...")
        registered = _register_spoofer_task()

        if registered:
            ok = _run_schtask("run", task_name)
            if ok:
                _print(f"[+] Started {name} via newly-registered Scheduled Task")
            return ok

        # Registration failed — fall back to direct elevated launch
        _print(f"[!] Could not register Scheduled Task for {name}. Trying direct elevated launch...")
        _start_spoofer_direct()
        return True  # best-effort, we can't track the PID via ShellExecute

    # ---- Optional services whose binary might not be present ----
    binary = svc.get("optional_binary")
    if binary:
        try:
            exists = Path(binary).exists()
        except PermissionError:
            exists = True   # locked/running — treat as present
        if not exists:
            _print(f"[!] {name}: binary not found at {binary}, skipping.")
            return False

    # ---- Don't double-start ----
    with _lock:
        proc = _processes.get(name)
        if proc and proc.poll() is None:
            return True

    # ---- Standard hidden subprocess ----
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
        _print(f"[+] Started {name} (pid {proc.pid})")
        return True
    except PermissionError as e:
        # Access denied — binary likely needs elevation (e.g. AdGuard Home binds port 53).
        # Fall back to ShellExecute runas so it gets admin rights without blocking the launcher.
        _print(f"[!] Failed to start {name} normally ({e}). Retrying with elevation...")
        exe = svc["args"][0]
        args_str = " ".join(f'"{a}"' for a in svc["args"][1:]) if len(svc["args"]) > 1 else ""
        cwd = svc.get("cwd", str(PROJECT_ROOT))
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, args_str, cwd,
                0,  # SW_HIDE
            )
            if ret > 32:
                _print(f"[+] Started {name} (elevated, hidden).")
                return True
            else:
                _print(f"[!] Elevated launch of {name} returned {ret} — UAC may have been denied.")
                return False
        except Exception as e2:
            _print(f"[!] Elevated launch of {name} failed: {e2}")
            return False
    except Exception as e:
        _print(f"[!] Failed to start {name}: {e}")
        return False


def start_all():
    for svc in SERVICES:
        _start_service(svc)


def stop_all():
    # Stop Scheduled Task services first
    for svc in SERVICES:
        if "schtask_name" in svc:
            task_name = svc["schtask_name"]
            _print(f"[*] Stopping {svc['name']} via Scheduled Task '{task_name}'...")
            _run_schtask("end", task_name)

    with _lock:
        procs = dict(_processes)
    for name, proc in procs.items():
        if proc.poll() is None:
            _print(f"[*] Stopping {name} (pid {proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    with _lock:
        _processes.clear()


def service_status() -> dict[str, bool]:
    """Returns {name: is_running} for every service."""
    status: dict[str, bool] = {}
    with _lock:
        for name, proc in _processes.items():
            status[name] = proc.poll() is None
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
            # Scheduled Task services are managed (and auto-restarted) by Task Scheduler
            if "schtask_name" in svc:
                continue
            # Optional services that were skipped at startup shouldn't be restarted
            binary = svc.get("optional_binary")
            if binary and not Path(binary).exists():
                continue
            name = svc["name"]
            with _lock:
                proc = _processes.get(name)
            if proc is not None and proc.poll() is not None:
                _print(f"[!] {name} exited (code {proc.returncode}), restarting...")
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
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse([4, 4, 60, 60], fill=(30, 30, 46, 255))
        draw.arc([12, 20, 52, 56], start=200, end=340, fill=(100, 220, 200, 255), width=5)
        draw.arc([20, 28, 44, 50], start=200, end=340, fill=(100, 220, 200, 200), width=4)
        draw.ellipse([29, 40, 35, 46], fill=(100, 220, 200, 255))
        return img
    except ImportError:
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
        icon.notify("Stopping all services...", "Network Companion")
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
        _print("[i] pystray not installed — running without tray icon.")
        _print(f"[i] Dashboard: http://localhost:{_dashboard_port()}")
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
        menu=_make_menu(None),
    )
    icon.menu = _make_menu(icon)

    def _update_tooltip():
        while True:
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
    os.chdir(PROJECT_ROOT)

    # --- Validate environment; download AdGuard if missing; warn about Npcap ---
    warnings = _validate_environment()   # fatal issues call sys.exit() internally

    _print("[i] Starting Network Companion...")

    # --- Start all services silently in the background ---
    try:
        start_all()
    except Exception as e:
        _msgbox(
            "Network Companion — Startup Error",
            f"Failed to start services:\n{e}\n\nCheck that no other instance is already running.\n\nSee tray_launcher.log for details.",
            0x10,
        )
        sys.exit(1)

    # --- Show any non-fatal warnings AFTER services are up (don't block startup) ---
    if warnings:
        warning_text = "\n\n".join(warnings)
        _print(f"[!] Startup warnings:\n{warning_text}")
        _msgbox(
            "Network Companion — Some features unavailable",
            warning_text + "\n\nAll other services are running normally.",
            0x30,  # MB_ICONWARNING
        )

    # --- Watchdog in background ---
    threading.Thread(target=_watchdog, daemon=True).start()

    # --- Run tray (blocks until user clicks Stop All & Exit) ---
    run_tray()

    # --- Cleanup ---
    stop_all()
    _print("[i] Goodbye.")
