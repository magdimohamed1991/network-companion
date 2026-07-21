"""
arp_spoofer.py — ARP-spoofing bandwidth capture AND policy enforcement for Network Companion.

WHAT THIS DOES
    For devices you've explicitly "armed" (bandwidth_armed=1 in the database, set from
    the dashboard), this sends forged ARP replies to both the device and your router so
    traffic between them flows through this machine's MAC address.

    Phase 3 change: THIS SCRIPT now does the actual packet forwarding itself, in Python —
    it no longer relies on Windows' IPEnableRouter (see install/enable_ip_forwarding.ps1
    -Disable, which must be applied + rebooted before running this). That's what makes
    per-device quota/schedule enforcement possible at all: Windows' own IP forwarding is a
    single global on/off switch, so it can't selectively block one spoofed device while
    still relaying another. Every packet addressed to this machine's MAC because of the
    spoof goes through database.get_effective_policy() (cached per device, refreshed every
    SPOOF_INTERVAL_SECONDS — not queried per packet, that would be far too slow):
        'none'     -> forward normally
        'throttle' -> token-bucket rate limit; packets over the budget are dropped
        'block'    -> dropped entirely, nothing forwarded

    Nothing is spoofed automatically. A device only gets touched after you explicitly
    arm it (database.arm_bandwidth_capture), and this script re-checks the armed list
    every SPOOF_INTERVAL_SECONDS so you can arm/disarm live from the dashboard.

    Two safety nets auto-disarm (and clear the DB flag, requiring an explicit re-arm)
    without you doing anything:
      - A device going offline is un-armed immediately, rather than continuing to spoof
        an address that DHCP might hand to a different device next.
      - A watchdog un-arms anything that's online but shows zero traffic for
        WATCHDOG_TIMEOUT_SECONDS — usually a sign the forwarding path broke rather than
        the device genuinely being idle. Note a fully-blocked device will also trip this
        after 10 minutes of legitimately-enforced silence; that's expected, not a bug —
        re-arm it if you want tracking to keep running while it stays blocked.
      Both show up in the dashboard's activity feed so you know tracking stopped and why.

REQUIREMENTS
    - Npcap, installed with "Support raw 802.11 traffic (and monitor mode) for wireless
      adapters" UNCHECKED and "Install Npcap in WinPcap API-compatible Mode" CHECKED:
      https://npcap.com/#download
    - install/enable_ip_forwarding.ps1 -Disable has been run (Phase 3 forwards traffic
      itself; leaving Windows' own forwarding on too can duplicate packets), and the
      machine has been rebooted.
    - This script itself must run as Administrator (raw packet injection requires it).
    - pip install scapy
    - Only use on a network you own or administer. This is the same technique used in
      genuine ARP-spoofing attacks — the only difference is whose network and whose
      consent. Some routers and devices (notably Android) surface an "ARP spoofing
      detected" warning when this runs; that is expected, not a malfunction.

RECOVERY
    If this ever exits uncleanly (power loss, task killed, etc.) and you're worried a
    device is stuck with a poisoned ARP cache, run:
        python arp_spoofer.py --restore-all
    Real ARP entries also self-heal on their own after a couple of minutes even with no
    action taken, since this script stops refreshing the forged ones.
"""

import argparse
import signal
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so `import database` finds the project root

from scapy.all import ARP, Ether, conf, get_if_list, send, sniff, srp

import database
from netutils import get_default_gateway

SPOOF_INTERVAL_SECONDS = 2
SAMPLE_INTERVAL_SECONDS = 10
ARP_RESOLVE_TIMEOUT = 3.0
WATCHDOG_TIMEOUT_SECONDS = 600  # zero traffic this long, while device is online, likely means forwarding broke

_stop_event = threading.Event()
_spoofed_targets: dict[str, dict] = {}  # mac -> {ip, router_ip, router_mac, sent, received, last_activity, policy, bucket}
_lock = threading.Lock()
_iface: str | None = None
_our_mac: str | None = None


class TokenBucket:
    """Simple drop-based rate limiter: refills continuously at `rate` bytes/sec, allows a
    packet through if enough tokens are banked, otherwise denies it (caller drops the
    packet) — relies on TCP's own congestion control to back off in response to the loss,
    rather than trying to queue/shape traffic smoothly. `capacity` allows a short burst
    (default 2 seconds worth) so it doesn't feel artificially choppy for bursty traffic
    like web page loads.
    """

    def __init__(self, rate_bytes_per_sec: float, capacity_bytes: float | None = None):
        self.rate = max(rate_bytes_per_sec, 1)
        self.capacity = capacity_bytes if capacity_bytes is not None else self.rate * 2
        self.tokens = self.capacity
        self.last_refill = time.time()

    def allow(self, size_bytes: int) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= size_bytes:
            self.tokens -= size_bytes
            return True
        return False


def get_mac(ip: str, timeout: float = ARP_RESOLVE_TIMEOUT) -> str | None:
    """Resolve a MAC via a live ARP request — not the (possibly stale/poisoned) OS cache."""
    kwargs = {"timeout": timeout, "verbose": False}
    if _iface:
        kwargs["iface"] = _iface
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), **kwargs)
    for _, received in ans:
        return received.hwsrc
    return None


def get_our_mac(iface: str | None) -> str | None:
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface) if iface else get_if_hwaddr(conf.iface)
    except Exception as e:
        print(f"[!] Could not resolve this machine's own MAC address: {e}")
        return None


def warn_if_ip_forwarding_still_enabled():
    """Phase 3 forwards packets itself — if Windows' own IPEnableRouter is ALSO still on
    (from the Phase 1/2 setup), packets would get forwarded twice. Best-effort check;
    silently skips if the registry can't be read (e.g. not on Windows, no permissions)."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
        value, _ = winreg.QueryValueEx(key, "IPEnableRouter")
        if value == 1:
            print("[!] WARNING: Windows IP forwarding (IPEnableRouter) is still enabled.")
            print("[!] This script now does its own forwarding — having both on can duplicate")
            print("[!] packets for armed devices. Run: install\\enable_ip_forwarding.ps1 -Disable")
            print("[!] (then reboot), or this may cause duplicate/garbled traffic.\n")
    except Exception:
        pass  # not on Windows, key missing, or no permission — can't check, don't block startup over it


def _send(pkt):
    if _iface:
        send(pkt, iface=_iface, verbose=False)
    else:
        send(pkt, verbose=False)


def spoof_once(target_ip: str, target_mac: str, impersonate_ip: str):
    """Tell target_ip that impersonate_ip now lives at our MAC address."""
    _send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=impersonate_ip))


def restore_once(target_ip: str, target_mac: str, real_ip: str, real_mac: str):
    """Undo a spoof: tell target_ip the TRUE mapping for real_ip. Sent 3x for reliability."""
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    for _ in range(3):
        _send(pkt)
        time.sleep(0.1)


def restore_all():
    """Shutdown path: restore every currently-spoofed target immediately, don't wait for cache timeout."""
    with _lock:
        targets = dict(_spoofed_targets)
    for mac, info in targets.items():
        try:
            restore_once(info["ip"], mac, info["router_ip"], info["router_mac"])
            restore_once(info["router_ip"], info["router_mac"], info["ip"], mac)
            database.log_spoof_event(mac, "restored", "clean shutdown")
            print(f"[+] Restored real ARP mapping for {info['ip']} ({mac})")
        except Exception as e:
            database.log_spoof_event(mac, "error", f"restore failed: {e}")
            print(f"[!] Failed to restore {info['ip']}: {e}")
    with _lock:
        _spoofed_targets.clear()


def _disarm_target(mac: str, info: dict, reason: str, event_type: str):
    """Shared cleanup path: restore real ARP, drop from local tracking, clear the DB flag
    so it doesn't silently re-arm next cycle, and log both the technical reason (spoof_log)
    and a dashboard-visible event (device_events)."""
    restore_once(info["ip"], mac, info["router_ip"], info["router_mac"])
    restore_once(info["router_ip"], info["router_mac"], info["ip"], mac)
    database.disarm_bandwidth_capture(mac, detail=reason)
    database.log_device_event(mac, event_type)
    print(f"[-] {reason}: {info['ip']} ({mac}) — ARP restored, un-armed in dashboard")


def _spoof_loop():
    """Re-poison ARP caches for every currently-armed, online device. Disarms (and clears
    the DB flag, requiring an explicit re-arm) anything that: the user removed from the
    armed list, went offline, or has gone silent long enough to suggest forwarding broke."""
    while not _stop_event.is_set():
        armed = database.get_armed_devices()
        armed_macs = set()

        for dev in armed:
            mac = dev["mac"]

            if not dev["is_online"]:
                # Device left the network — disarm rather than keep spoofing a phantom
                # target (also avoids accidentally MITM-ing whoever DHCP reassigns that IP to).
                with _lock:
                    info = _spoofed_targets.pop(mac, None)
                if info:
                    _disarm_target(mac, info, "device went offline", "offline_disarm")
                continue

            if not dev["ip"] or not dev["router_ip"]:
                continue

            armed_macs.add(mac)

            with _lock:
                info = _spoofed_targets.get(mac)

            if info is None:
                router_mac = get_mac(dev["router_ip"])
                if router_mac is None:
                    print(f"[!] Could not resolve router MAC for {dev['router_ip']}, skipping {dev['ip']}")
                    continue
                info = {
                    "ip": dev["ip"], "router_ip": dev["router_ip"], "router_mac": router_mac,
                    "sent": 0, "received": 0, "last_activity": time.time(),
                    "policy": {"action": "none", "throttle_rate_kbps": None, "reason": ""}, "bucket": None,
                }
                with _lock:
                    _spoofed_targets[mac] = info
                database.log_spoof_event(mac, "armed", f"started spoofing {dev['ip']}")
                print(f"[+] Now capturing bandwidth for {dev['ip']} ({mac})")
            elif info["ip"] != dev["ip"]:
                # DHCP handed this device a new IP since we started tracking it — resync,
                # rather than keep spoofing the address it no longer has.
                print(f"[i] {mac} changed IP {info['ip']} -> {dev['ip']}, resyncing")
                with _lock:
                    info["ip"] = dev["ip"]
                    info["last_activity"] = time.time()  # don't immediately watchdog-trip on the resync itself

            # Refresh the policy every cycle (quota/schedule can change any time via the
            # dashboard, and a schedule window's start/end is itself time-dependent) —
            # cached here rather than hit per-packet, since the relay checks this on every
            # single packet and a SQLite query per packet would be far too slow.
            new_policy = database.get_effective_policy(mac)
            with _lock:
                prev_action = info["policy"]["action"]
                info["policy"] = new_policy
                if new_policy["action"] == "throttle":
                    rate_bytes = (new_policy["throttle_rate_kbps"] or 0) * 1024 / 8
                    if info["bucket"] is None or info["bucket"].rate != rate_bytes:
                        info["bucket"] = TokenBucket(rate_bytes) if rate_bytes > 0 else None
                else:
                    info["bucket"] = None
            if new_policy["action"] != prev_action:
                print(f"[i] {dev['ip']} ({mac}) policy: {prev_action} -> {new_policy['action']} ({new_policy['reason']})")
                database.log_spoof_event(mac, "policy_change", f"{prev_action} -> {new_policy['action']}: {new_policy['reason']}")

            # Watchdog: online, armed, but genuinely nothing observed in a long time —
            # more likely a broken forward path than a device that's simply idle.
            if time.time() - info["last_activity"] > WATCHDOG_TIMEOUT_SECONDS:
                with _lock:
                    _spoofed_targets.pop(mac, None)
                _disarm_target(
                    mac, info,
                    f"no traffic observed for {WATCHDOG_TIMEOUT_SECONDS}s despite being online — likely broken forwarding",
                    "watchdog_disarm",
                )
                continue

            spoof_once(info["ip"], mac, info["router_ip"])
            spoof_once(info["router_ip"], info["router_mac"], info["ip"])

        # Anything still tracked locally but no longer in this cycle's armed_macs was
        # explicitly disarmed via the dashboard — restore it.
        with _lock:
            currently_spoofed = set(_spoofed_targets.keys())
        for mac in currently_spoofed - armed_macs:
            with _lock:
                info = _spoofed_targets.pop(mac, None)
            if info:
                restore_once(info["ip"], mac, info["router_ip"], info["router_mac"])
                restore_once(info["router_ip"], info["router_mac"], info["ip"], mac)
                database.log_spoof_event(mac, "disarmed", "removed from armed list")
                print(f"[-] Stopped capturing {info['ip']} — ARP restored")

        # Write a heartbeat every cycle so the dashboard's relay_alive check has a
        # reliable liveness signal that only this process can produce — independent of
        # arm/disarm events which database.arm_bandwidth_capture() also writes to spoof_log.
        database.set_notifier_state("arp_spoofer_heartbeat", str(time.time()))

        _stop_event.wait(SPOOF_INTERVAL_SECONDS)


def _relay_loop():
    """The actual forwarding engine. Windows' own IP stack is NOT relied on anymore (see
    install/enable_ip_forwarding.ps1 -Disable) — every packet addressed to our MAC because
    of the ARP spoof is a decision point:
        policy 'block'    -> drop silently (existing connections just hang/timeout)
        policy 'throttle' -> token-bucket check; forward if within budget, drop if not
        policy 'none'     -> forward as normal
    Byte counting and the watchdog's last_activity both happen here regardless of the
    policy outcome — a throttled or even blocked device still generates 'activity' from
    its own perspective (it's trying to send), so watchdog false-positives are avoided by
    only counting genuinely observed packets, not by policy outcome.
    """

    def forward(pkt, eth_dst: str):
        pkt = pkt.copy()
        pkt[Ether].src = _our_mac
        pkt[Ether].dst = eth_dst
        from scapy.all import sendp
        sendp(pkt, iface=_iface, verbose=False)

    def on_packet(pkt):
        if "IP" not in pkt or "Ether" not in pkt:
            return
        if _our_mac and pkt[Ether].dst.lower() != _our_mac.lower():
            return  # not part of a flow we're spoofing

        size = len(pkt)
        now = time.time()
        src_ip, dst_ip = pkt["IP"].src, pkt["IP"].dst

        with _lock:
            target_mac, info, direction = None, None, None
            for m, i in _spoofed_targets.items():
                if src_ip == i["ip"]:
                    target_mac, info, direction = m, i, "out"  # device -> router
                    break
                elif dst_ip == i["ip"]:
                    target_mac, info, direction = m, i, "in"   # router -> device
                    break
            if info is None:
                return

            if direction == "out":
                info["sent"] += size
            else:
                info["received"] += size
            info["last_activity"] = now

            action = info["policy"]["action"]
            bucket = info["bucket"]

        if action == "block":
            return  # dropped — no forward call at all

        if action == "throttle":
            if bucket is None or not bucket.allow(size):
                return  # over the rate limit this instant, drop and let TCP back off

        next_hop_mac = info["router_mac"] if direction == "out" else target_mac
        try:
            forward(pkt, next_hop_mac)
        except Exception as e:
            print(f"[!] Forward failed for {src_ip}->{dst_ip}: {e}")

    def flush_loop():
        while not _stop_event.is_set():
            _stop_event.wait(SAMPLE_INTERVAL_SECONDS)
            with _lock:
                for mac, info in _spoofed_targets.items():
                    if info["sent"] or info["received"]:
                        database.record_bandwidth_sample(mac, info["sent"], info["received"])
                        info["sent"] = 0
                        info["received"] = 0

    threading.Thread(target=flush_loop, daemon=True).start()

    kwargs = {"prn": on_packet, "store": False, "stop_filter": lambda p: _stop_event.is_set()}
    if _iface:
        kwargs["iface"] = _iface
    sniff(**kwargs)


def handle_shutdown(signum, frame):
    print("\n[!] Shutting down — restoring ARP tables...")
    _stop_event.set()
    restore_all()
    sys.exit(0)


def main():
    global _iface, _our_mac

    parser = argparse.ArgumentParser(description="ARP-spoofing bandwidth capture — only touches devices armed in the dashboard")
    parser.add_argument("--iface", help="Npcap interface name to bind to. See --list-interfaces if unsure.")
    parser.add_argument("--list-interfaces", action="store_true", help="List interfaces Npcap can see, then exit")
    parser.add_argument("--restore-all", action="store_true", help="Send corrective ARP for every known device and exit (recovery mode)")
    args = parser.parse_args()

    if args.list_interfaces:
        for name in get_if_list():
            print(name)
        print("\nPass the correct one with --iface \"<name>\". The active WiFi/Ethernet")
        print("adapter is usually the one that is NOT named for WSL, Docker, VPN, or Hyper-V.")
        return

    _iface = args.iface
    database.init_db()

    if args.restore_all:
        print("[!] Recovery mode: restoring ARP for every device in the database...")
        gw = get_default_gateway()
        router_mac = get_mac(gw) if gw else None
        if not gw or not router_mac:
            print("[!] Could not determine router IP/MAC — nothing to restore, or resolve it manually.")
            return
        for dev in database.get_all_devices():
            if dev["ip"]:
                restore_once(dev["ip"], dev["mac"], gw, router_mac)
                restore_once(gw, router_mac, dev["ip"], dev["mac"])
        print("[+] Done.")
        return

    _our_mac = get_our_mac(_iface)
    if _our_mac is None:
        print("[!] Could not resolve this machine's own MAC address on the chosen interface.")
        print("[!] The relay can't forward traffic without knowing its own address. Try")
        print("[!] passing --iface explicitly (see --list-interfaces) and confirm Npcap is installed.")
        return

    warn_if_ip_forwarding_still_enabled()

    print(f"[i] This machine's MAC on the active interface: {_our_mac}")
    print("[i] Actively relaying traffic for armed devices (this process forwards it now,")
    print("[i] not Windows) — applying each device's quota/schedule policy per packet.")
    print("[i] Press Ctrl+C to stop and restore all ARP tables cleanly.")
    if not _iface:
        print("[i] No --iface given; scapy will guess. If capture finds nothing, run")
        print("    --list-interfaces and pass the right one explicitly.\n")

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    threading.Thread(target=_spoof_loop, daemon=True).start()

    try:
        _relay_loop()
    finally:
        _stop_event.set()
        restore_all()


if __name__ == "__main__":
    main()
