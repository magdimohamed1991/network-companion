"""
scanner.py — passive device discovery for Network Companion.

Unlike arp_spoofer.py, this is safe to run continuously with no special setup: it does a
ping sweep to populate Windows' own ARP cache, then reads `arp -a` for IP/MAC pairs. No
Npcap, no admin rights, no raw sockets, nothing that touches other devices' traffic.

Runs forever, re-scanning every SCAN_INTERVAL_SECONDS, so this is one of the two
long-running processes (the other is arp_spoofer.py) that install/*.ps1 sets up as a
Windows service.

Hostname resolution strategy (tried in order, first non-None wins):
  1. Reverse-DNS / PTR   — fast, works when the router runs a local DNS server
  2. NetBIOS (nbtstat)   — queries the device directly; works for Windows PCs and many
                           IoT devices even when there's no router DNS support
  3. mDNS / Bonjour      — passive listener via zeroconf; catches Apple devices and
                           modern IoT that advertise a real .local hostname
"""

import argparse
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import database
from netutils import get_local_ip
from oui_vendors import lookup_vendor, lookup_device_type

SCAN_INTERVAL_SECONDS = 60
PING_TIMEOUT_MS = 300
PING_WORKERS = 64

# ---------------------------------------------------------------------------
# mDNS cache — populated by the background ZeroconfListener; read by the scan
# ---------------------------------------------------------------------------
_mdns_names: dict[str, str] = {}   # ip -> .local hostname

try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

    class _ZeroconfListener:
        """Passive listener that caches IP→hostname mappings from mDNS announcements."""

        def __init__(self, zc: "Zeroconf"):
            self._zc = zc

        def _register(self, name: str, info: "ServiceInfo | None") -> None:
            if info is None:
                return
            hostname = info.server  # e.g. "mydevice.local."
            if not hostname:
                return
            hostname = hostname.rstrip(".")
            for addr_bytes in info.addresses:
                try:
                    ip = socket.inet_ntoa(addr_bytes)
                    _mdns_names[ip] = hostname
                except OSError:
                    pass

        def add_service(self, zc: "Zeroconf", svc_type: str, name: str) -> None:
            info = zc.get_service_info(svc_type, name)
            self._register(name, info)

        def update_service(self, zc: "Zeroconf", svc_type: str, name: str) -> None:
            info = zc.get_service_info(svc_type, name)
            self._register(name, info)

        def remove_service(self, zc: "Zeroconf", svc_type: str, name: str) -> None:
            pass

    def _start_mdns_listener() -> None:
        """Start a background Zeroconf browser for the most common service types."""
        zc = Zeroconf()
        listener = _ZeroconfListener(zc)
        # Browse the service types most commonly used by consumer devices
        for svc in (
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_googlecast._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_homekit._tcp.local.",
            "_matter._tcp.local.",
            "_printer._tcp.local.",
            "_ipp._tcp.local.",
            "_smb._tcp.local.",
            "_device-info._tcp.local.",
        ):
            ServiceBrowser(zc, svc, listener)
        # Keep the Zeroconf instance alive; it runs its own daemon threads
        # so we don't need to join it.

    _start_mdns_listener()
    print("[i] mDNS/Bonjour listener started (zeroconf)")
except ImportError:
    print("[!] zeroconf not installed — mDNS hostname resolution disabled. "
          "Run: pip install zeroconf==0.132.2")


def get_all_local_subnets() -> list[str]:
    """
    Return all unique /24 prefixes for this machine's private IPv4 interfaces.
    Handles the common case where the machine is on both a home LAN (192.168.x.x)
    and a hotspot/VPN (10.x.x.x) simultaneously — we want to scan all of them.
    Falls back to the single active-socket IP if nothing else works.
    """
    prefixes = set()
    try:
        # ipconfig gives us all bound addresses — much more reliable than
        # the single-socket trick which returns whichever interface routes to 8.8.8.8
        output = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
        for match in re.finditer(r"IPv4 Address[ .]*:\s*([\d.]+)", output):
            ip = match.group(1).strip()
            # Skip loopback and APIPA
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            prefix = ".".join(ip.split(".")[:3])
            prefixes.add(prefix)
    except Exception:
        pass

    if not prefixes:
        # Fallback: single active-route IP
        try:
            ip = get_local_ip()
            prefixes.add(".".join(ip.split(".")[:3]))
        except Exception:
            pass

    return sorted(prefixes)


def subnet_hosts(prefix: str) -> list[str]:
    """Return all host addresses for a /24 prefix (e.g. '192.168.1')."""
    return [f"{prefix}.{i}" for i in range(1, 255)]


def ping(ip: str) -> None:
    subprocess.run(
        ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def ping_sweep(hosts: list[str]):
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        list(pool.map(ping, hosts))


def read_arp_table() -> list[dict]:
    """Returns list of {ip, ipv6, mac} from `arp -a` and `netsh interface ipv6 show neighbors`."""
    pairs = {} # mac -> {ip, ipv6, mac}
    
    # IPv4 via arp -a
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
        for line in output.splitlines():
            match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
            if match:
                ip, mac_dashed, entry_type = match.groups()
                if entry_type.lower() != "dynamic": continue
                mac = mac_dashed.replace("-", ":").lower()
                if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"): continue
                pairs[mac] = {"ip": ip, "ipv6": None, "mac": mac}
    except Exception as e:
        print(f"[!] Could not run arp -a: {e}")

    # IPv6 via netsh
    try:
        output = subprocess.check_output("netsh interface ipv6 show neighbors", shell=True, text=True, errors="ignore")
        # Example: fe80::1                          00-11-22-33-44-55  Reachable
        for line in output.splitlines():
            match = re.match(r"\s*([0-9a-fA-F:]+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
            if match:
                ipv6, mac_dashed, state = match.groups()
                if state.lower() not in ("reachable", "stale", "delay", "probe"): continue
                mac = mac_dashed.replace("-", ":").lower()
                if mac in pairs:
                    pairs[mac]["ipv6"] = ipv6
                else:
                    pairs[mac] = {"ip": None, "ipv6": ipv6, "mac": mac}
    except Exception:
        pass # IPv6 might not be enabled or supported

    return list(pairs.values())


def resolve_hostname(ip: str, timeout: float = 0.5) -> str | None:
    """Reverse-DNS lookup. Returns None if the result is just the IP itself (no real hostname)."""
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
        # gethostbyaddr sometimes returns the IP unchanged when there's no PTR record
        if name and name != ip:
            return name
        return None
    except (socket.herror, socket.timeout, OSError):
        return None


def resolve_netbios(ip: str) -> str | None:
    """
    Query the device directly via NetBIOS name service (nbtstat -A <ip>).

    Looks for the row with the <20> suffix (Workstation Service), which is the
    machine name that Windows registers and most NetBIOS-aware IoT devices
    announce.  Falls back to any <00> UNIQUE entry if <20> isn't present.

    Returns None on timeout, error, or if the device doesn't speak NetBIOS.
    Typical round-trip is well under 2 seconds on a local LAN.
    """
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True, text=True, timeout=4, errors="ignore",
        )
        output = result.stdout
        # nbtstat -A output has rows like:
        #   MYMACHINE      <20>  UNIQUE      Registered
        #   MYMACHINE      <00>  UNIQUE      Registered
        # Prefer the <20> (Workstation Service) entry; it's the "real" hostname.
        for suffix in ("<20>", "<00>"):
            for line in output.splitlines():
                if suffix in line and "UNIQUE" in line:
                    # Name occupies the first whitespace-delimited field
                    name = line.split()[0].strip()
                    if name:
                        return name
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def resolve_mdns(ip: str) -> str | None:
    """
    Look up a cached mDNS / Bonjour hostname for this IP.

    The cache is populated passively by the background Zeroconf listener that
    starts at module load time.  If zeroconf isn't installed the cache is always
    empty and this always returns None.
    """
    return _mdns_names.get(ip)


def run_one_scan(subnet_override: list[str] | None = None):
    started = time.time()

    if subnet_override:
        all_hosts = subnet_override
        subnets_label = "override"
    else:
        prefixes = get_all_local_subnets()
        all_hosts = []
        for p in prefixes:
            all_hosts.extend(subnet_hosts(p))
        subnets_label = ", ".join(f"{p}.0/24" for p in prefixes)

    print(f"[i] Scanning {len(all_hosts)} addresses across: {subnets_label} ...")
    ping_sweep(all_hosts)
    arp_pairs = read_arp_table()

    seen_macs = set()
    new_count = 0
    for entry in arp_pairs:
        ip, ipv6, mac = entry["ip"], entry["ipv6"], entry["mac"]
        # Try hostname sources in order; first non-None wins.
        hostname = None
        if ip:
            hostname = (
                resolve_hostname(ip)          # 1. Reverse-DNS / router PTR
                or resolve_mdns(ip)           # 2. mDNS cache (populated passively)
                or resolve_netbios(ip)        # 3. NetBIOS direct query
            )
        vendor = lookup_vendor(mac)
        device_type = lookup_device_type(mac, hostname, ip)
        is_new = database.upsert_device(mac, ip, ipv6, hostname, vendor, device_type)
        seen_macs.add(mac)
        if is_new:
            new_count += 1
            label = hostname or vendor or mac
            print(f"[+] New device: {label} — {ip} ({mac})")

    database.mark_stale_devices_offline(seen_macs)
    database.log_scan(started, time.time(), len(seen_macs), subnets_label)
    print(f"[i] Scan complete: {len(seen_macs)} devices online, {new_count} new. "
          f"({time.time() - started:.1f}s)")


def main():
    parser = argparse.ArgumentParser(description="Passive device discovery — ping sweep + ARP table")
    parser.add_argument("--once", action="store_true", help="Run a single scan and exit, instead of looping")
    parser.add_argument("--subnet", help="Override auto-detected subnet, e.g. 192.168.1 (no trailing octet)")
    args = parser.parse_args()

    database.init_db()
    subnet_override = [f"{args.subnet}.{i}" for i in range(1, 255)] if args.subnet else None

    if args.once:
        run_one_scan(subnet_override)
        return

    print(f"[i] Scanning every {SCAN_INTERVAL_SECONDS}s. Ctrl+C to stop.\n")
    while True:
        try:
            run_one_scan(subnet_override)
        except Exception as e:
            print(f"[!] Scan failed, will retry next cycle: {e}")
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
