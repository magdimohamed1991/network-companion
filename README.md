# Network Companion

A free, self-hosted, always-on home network dashboard: connected devices, what they're
querying via DNS (sites visited), and per-device bandwidth for devices you explicitly
opt in to tracking. Runs entirely on your own Windows PC — no cloud, no subscription,
no Lovable dependency.

## Architecture — why it's built this way

| Piece | What it does | Runs as |
|---|---|---|
| `scanner/scanner.py` | Ping sweep + ARP table → device list | Native Windows Python, no admin needed |
| `scanner/arp_spoofer.py` | ARP-spoof relay: bandwidth capture + quota/schedule enforcement | Native Windows Python, **Administrator** |
| AdGuard Home | DNS resolver for your LAN → per-device query log (sites visited) | Managed child process (started by tray launcher from `adguard/AdGuardHome.exe`) |
| `dashboard/` | FastAPI backend + single-file HTML frontend, ties it all together | Native Windows Python |
| `maintenance.py` | Daily data retention: rolls up old bandwidth samples, prunes old logs | Native Windows Python, runs once/day |
| `notifier.py` | Watches for new devices, watchdog events, and quota crossings → Windows toast / Telegram | Native Windows Python |
| `snmp_monitor.py` | Phase 4: Router-level bandwidth monitoring via SNMP | Native Windows Python |

Everything runs **natively on Windows**, not inside WSL2 or Docker. That's a deliberate
choice, not a default: WSL2 sits behind NAT, and Docker Desktop's mirrored-networking
mode (the fix for that) has open, unresolved bugs as of this year. Native Windows has
unobstructed access to your real network adapter, which this whole project depends on.

### Phase 3: `arp_spoofer.py` forwards traffic itself now

Through Phase 2, Windows' own IP forwarding (`IPEnableRouter`) relayed spoofed traffic —
fine for passive measurement, but it's a single global on/off switch, so it can't
selectively block one device's traffic while still relaying another's. Real per-device
quota/schedule enforcement needs the decision made per-packet, so **`arp_spoofer.py` now
does its own forwarding in Python** instead of relying on the OS:
- policy `none` → forward normally
- policy `throttle` → a token bucket drops packets over the configured rate, letting TCP
  back off naturally (simpler and safer than trying to smoothly queue/shape traffic —
  trade-off is it feels a bit choppy rather than perfectly smooth)
- policy `block` → dropped entirely; existing connections just hang until they time out
  on the device's own side, same as any tool in this class — no attempt to send a clean
  "connection closed" signal, since crafting that correctly is its own can of worms

**This means `enable_ip_forwarding.ps1` needs to be run with `-Disable` now** (see setup
step 3 below) — leaving Windows' own forwarding on *and* running this relay would
double-forward every packet for armed devices.

### Two safety nets that run automatically

- **Offline auto-disarm**: if an armed device leaves the network, tracking stops
  immediately rather than continuing to spoof an address DHCP might hand to a different
  device next.
- **Watchdog auto-disarm**: if an armed device is online but shows *zero* traffic for
  10 minutes, that's more likely broken forwarding than genuine idleness, so it
  auto-disarms and flags it — check `install/enable_ip_forwarding.ps1` was applied and
  survived a reboot if you see this a lot.

Both clear the device's armed flag and show up in the dashboard's activity feed, so
tracking never silently resumes without you choosing to re-arm it.

### What's genuinely achievable, and what isn't

- **Device list**: fully real, via ARP/ping — reliable, no caveats. Supports **IPv6** (via `netsh`).
- **Device tagging**: add custom tags to group or label devices (e.g. "Kids", "Work", "SmartHome").
- **Sites visited**: fully real, but domain-level (DNS queries), not full URLs — that's
  what any DNS-based tool gives you, AdGuard Home included.
- **Bandwidth per device**: real, for devices you **arm**, via ARP spoofing — this is an
  active MITM technique. It's legitimate on a network you own, but only arm devices you
  actually want tracked, not everything by default, and expect the occasional "ARP
  spoofing detected" notice on some devices (normal, not a bug).
- **Global Bandwidth**: Phase 4 adds **Router SNMP** support to track total network usage directly from your router's WAN interface.
- **PWA support**: Install the dashboard as an app on your phone or PC for quick access.

---

## Setup — follow this order

### 1. Python for Windows (native, not WSL2)
If you don't already have it: [python.org/downloads](https://www.python.org/downloads/),
check **"Add python.exe to PATH"** during install.

```
cd network-companion
pip install -r requirements.txt
```

### 2. Npcap
Download from [npcap.com](https://npcap.com/#download), run the installer as
Administrator. Leave **"Install Npcap in WinPcap API-compatible Mode"** checked (it's on
by default). Leave the 802.11 raw-capture option unchecked — not needed here. **Reboot
after installing.**

### 3. Turn OFF Windows IP forwarding (the relay handles this itself now)
```powershell
# In an Administrator PowerShell:
cd network-companion\install
Set-ExecutionPolicy -Scope Process Bypass -Force
.\enable_ip_forwarding.ps1 -Disable
```
**Reboot** — this setting is only read at boot. (If you set this up before Phase 3 and
already had it enabled, this step turns it back off — see the Phase 3 architecture note
above for why.)

### 4. AdGuard Home (bundled in the `adguard/` folder — no separate install)
1. Download the Windows build from [AdGuard Home's GitHub releases](https://github.com/AdguardTeam/AdGuardHome/releases),
   and extract `AdGuardHome.exe` (and any accompanying files) into **`network-companion/adguard/`**.
   This exact path matters — `tray_launcher.py` (NetworkCompanion.exe) looks for
   `adguard/AdGuardHome.exe` relative to the project root and starts it as a managed
   background process. If the file isn't there, AdGuard is silently skipped and DNS
   tracking won't work, but everything else still runs.
2. Run it once manually to complete initial setup:
   ```
   adguard\AdGuardHome.exe -w adguard
   ```
   It starts on port 3000 — open `http://localhost:3000` in your browser and complete
   the setup wizard (pick an admin username/password; **you'll need these for config.json
   in step 6**). Press Ctrl+C when done; `tray_launcher.py` takes it from here.

> **Upgrading from the old install instructions?** If you previously ran
> `AdGuardHome.exe -s install` to register AdGuard as a Windows service, run
> `AdGuardHome.exe -s uninstall` first (in an Administrator terminal) before moving the
> binary here. Leaving the service registered means two copies would race for port 3000.

### 5. Point your router's DNS at this machine
In your router's admin page (usually `http://192.168.1.1` or similar), find DHCP
settings and set the DNS server to this PC's LAN IP (run `ipconfig` to find it,
"IPv4 Address"). This is what makes AdGuard Home see queries from your *other* devices,
not just this PC — without it, you'd only get sites-visited data for this one machine.

### 6. Configure Network Companion
```
python config.py
```
Enter the AdGuard Home URL (`http://127.0.0.1:3000` if running on this same machine)
and the admin username/password from step 4.

### 7. Test each piece manually before making anything persistent
```
# Terminal 1 — should start finding devices within ~60s
python scanner\scanner.py

# Terminal 2 (Administrator) — if it finds nothing, run --list-interfaces first
# and pass the right adapter explicitly with --iface
python scanner\arp_spoofer.py --list-interfaces
python scanner\arp_spoofer.py --iface "<the real one>"

# Terminal 3
python -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8642
```
Open `http://localhost:8642` — you should see devices appearing. Try arming one from the
dashboard and confirm Terminal 2 logs `Now capturing bandwidth for ...`. Ctrl+C each
terminal when satisfied; you should see arp_spoofer.py print `Restored real ARP mapping`
before it exits.

### 8. Make it persistent
```powershell
# Administrator PowerShell:
cd network-companion\install
.\register_tasks.ps1
```
This registers **two** Scheduled Tasks: `NetworkCompanion-ArpSpoofer` (starts at login
with elevated rights — the only service that needs them) and `NetworkCompanion-Maintenance`
(runs once daily at 4am).

All other services (Dashboard, Scanner, Notifier, SNMP Monitor, Anomaly Detector, and
AdGuard Home) are started directly by **NetworkCompanion.exe** (the tray launcher) —
double-click it to start everything. It also watches for crashes and restarts services
automatically. Its startup log is written to `tray_launcher.log` in the project root —
check there first if something isn't starting.

> **If you previously ran `register_tasks.ps1` from an older version**, remove the now-
> redundant at-login tasks before re-running:
> ```powershell
> foreach ($t in @("NetworkCompanion-Scanner","NetworkCompanion-Dashboard",
>     "NetworkCompanion-Notifier","NetworkCompanion-SNMPMonitor",
>     "NetworkCompanion-AnomalyDetector")) {
>     Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
> }
> ```

---

## Access control (Phase 3)

Two independent ways to restrict a device, both requiring it to be armed first:

**Quota action** — in a device's expanded panel, "When over quota" controls what happens
once monthly usage crosses the quota you set: nothing (default), throttle to a rate you
pick, or block outright.

**Scheduled restrictions** — add rules like "block 22:00–07:00, every day" per device.
Pick the days, a time window (wrapping past midnight is fine — a Wednesday-night rule
correctly extends into Thursday morning), and block or throttle. A device can have
multiple rules; if any enabled rule's window is currently active, it applies. If a quota
action and a schedule rule are both active at once, whichever is more restrictive wins
(block beats throttle beats none).

**Emergency unblock** — the red button in the header disarms bandwidth tracking (and
therefore every policy) for every device immediately, restoring normal connectivity
regardless of what any rule says. Use it if a policy seems to be misbehaving; you'll need
to re-arm devices afterward if you want tracking to continue.

## Day to day

Dashboard: `http://localhost:8642` on this PC, or `http://<this-PC's-IP>:8642` from your
phone or any other device on the same network.

- Click a device's name to rename it.
- Click "+ track bandwidth" to arm it (starts within a couple seconds).
- Expand a device to see sites visited, set a monthly quota, or disarm tracking.

## Notifications

Both are optional and independently toggleable in `config.json`. Re-run `python
config.py` any time to change these, or edit the file directly.

**Windows toast** — on by default, zero setup, but only visible if you're at this PC.

**Telegram** — reaches your phone. Two-minute setup:
1. In Telegram, message **@BotFather** → `/newbot` → follow the prompts (pick any name
   and a unique username ending in `bot`). It replies with a token that looks like
   `123456789:ABCdefGHIjklMNOpqrsTUVwxyz` — that's your `telegram_bot_token`.
2. Send your new bot any message (e.g. "hi") so it has something to reply to.
3. In a browser, visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` and find
   `"chat":{"id": ...}` in the response — that number is your `telegram_chat_id`.
4. Put both in `config.json` (or re-run `python config.py`) and set `notify_telegram`
   to `true`.

What triggers a notification (edit `notify_event_types` / `quota_alert_thresholds` in
`config.json` to change): a new device joining, `watchdog_disarm` events, and quota
usage crossing 80% or 100%. Each (device, month, threshold) combination only fires once.

## Recovery

If `arp_spoofer.py` ever exits uncleanly (power loss, killed process) and you're unsure
whether a device is stuck with a spoofed ARP entry:
```
python scanner\arp_spoofer.py --restore-all
```
It also self-heals on its own after a couple of minutes with no action needed, since
nothing keeps refreshing the forged entries once the process is gone.

## Troubleshooting

- **arp_spoofer.py finds no traffic / devices seem to lose connectivity when armed** —
  almost always the wrong network interface. Run `--list-interfaces` and pass your real
  Wi-Fi/Ethernet adapter explicitly with `--iface`; avoid anything named for WSL,
  Hyper-V, Docker, or a VPN.
- **Sites-visited panel says AdGuard unreachable** — confirm `adguard/AdGuardHome.exe`
  is present and running (check `tray_launcher.log` for a `[!] AdGuard Home: binary not
  found` line). If it's running but unreachable, confirm `config.json`'s URL/credentials
  match what you set in the AdGuard setup wizard.
- **Devices only show for this PC, not the whole house** — step 5 (router DNS) wasn't
  completed, or the router cached the old DNS setting; reboot the router after changing it.
- **Scheduled tasks aren't running** — `Get-ScheduledTask -TaskName "NetworkCompanion-*"`
  in an Administrator PowerShell to check status; `Start-ScheduledTask -TaskName "..."`
  to kick one manually and watch for errors.
- **Armed device's connection feels flaky, duplicated, or garbled** — almost always
  `IPEnableRouter` still being enabled alongside the Phase 3 relay (see step 3 — it needs
  to be `-Disable`d, not enabled, now). Check with:
  `Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name IPEnableRouter`
  — arp_spoofer.py also prints a warning at startup if it detects this.
- **A device seems stuck blocked when it shouldn't be** — click the emergency unblock
  button, then check the device's quota/schedule settings; the policy badge on its row
  shows the current reason when hovered.

## Project layout
```
network-companion/
├── database.py              # shared SQLite layer
├── netutils.py               # gateway/local-IP detection
├── config.py                 # settings (config.json, created on first run)
├── adguard_client.py         # AdGuard Home REST API client
├── maintenance.py             # daily data retention (rollup + pruning)
├── notifier.py                 # watches events + quota, triggers alerts
├── notifications.py            # Windows toast / Telegram send logic
├── requirements.txt
├── scanner/
│   ├── scanner.py             # passive device discovery
│   ├── arp_spoofer.py         # opt-in bandwidth capture
│   └── oui_vendors.py         # offline MAC vendor lookup
├── dashboard/
│   ├── main.py                 # FastAPI backend
│   └── static/index.html       # single-file frontend
└── install/
    ├── enable_ip_forwarding.ps1
    └── register_tasks.ps1
```
