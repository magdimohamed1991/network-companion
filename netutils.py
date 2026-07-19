"""netutils.py — small dependency-free helpers shared by the scanner, spoofer, and dashboard."""

import re
import socket
import subprocess


def get_default_gateway() -> str | None:
    """Parse `ipconfig` for the first non-empty IPv4 default gateway."""
    try:
        output = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
    except Exception:
        return None
    for match in re.finditer(r"Default Gateway[ .]*:\s*([\d.]+)", output):
        ip = match.group(1).strip()
        if ip and ip != "0.0.0.0":
            return ip
    return None


def get_local_ip() -> str:
    """The IP of this machine's active interface, found without sending real traffic."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()
