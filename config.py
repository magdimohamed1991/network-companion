"""
config.py — settings for Network Companion, stored in config.json next to this file.

Kept deliberately simple (one JSON file, no env var framework) since this is a personal,
single-machine tool. config.json is created interactively the first time the dashboard
is run if it doesn't already exist; edit it directly any time after that.
"""

import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

DEFAULTS = {
    "adguard_url": "http://127.0.0.1:3000",
    "adguard_username": "",
    "adguard_password": "",
    "router_ip": "",  # leave blank to auto-detect via netutils.get_default_gateway()
    "dashboard_port": 8642,
    # Phase 2: notifications — Windows toast needs zero setup; Telegram reaches your
    # phone but needs a bot token + chat id (see README "Notifications" section).
    "notify_windows_toast": True,
    "notify_telegram": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "notify_event_types": ["new_device", "watchdog_disarm"],
    "quota_alert_thresholds": [80, 100],
    # Phase 4: SNMP for router-level bandwidth
    "snmp_enabled": False,
    "snmp_community": "public",
    "snmp_version": 2,  # 1 or 2
    "snmp_wan_index": 1,  # interface index for WAN
    # Anomaly detection
    "anomaly_alert_new_mac": True,
    "anomaly_quiet_hours": [{"start": 1, "end": 6}],   # alert on traffic between 1am-6am
    "anomaly_min_spike_mb": 50,
    "anomaly_spike_factor": 5.0,
    "anomaly_auto_block_rules": [],   # e.g. ["RULE_HIGH_UPLOAD"] to auto-block
    # Auth — set auth_enabled: true and add users via the admin panel or CLI
    # First admin is created automatically if auth_enabled is true and no users exist
    "auth_enabled": False,
    "auth_secret_key": "",   # fill in a random 32+ char string when enabling auth
    "auth_token_expire_hours": 24,
    "auth_initial_admin_password": "",  # used once to bootstrap the first admin account
}


def load() -> dict:
    if not CONFIG_PATH.exists():
        save(DEFAULTS)
        return dict(DEFAULTS)
    with open(CONFIG_PATH, "r") as f:
        cfg = json.load(f)
    # Backfill any keys added in later versions of this file
    for key, value in DEFAULTS.items():
        cfg.setdefault(key, value)
    return cfg


def save(cfg: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def run_first_time_setup():
    """Interactive prompt, only used if config.json doesn't exist yet."""
    print("First-time setup — Network Companion")
    print("(press Enter to accept the default shown in [brackets])\n")
    cfg = dict(DEFAULTS)

    cfg["adguard_url"] = input(f"AdGuard Home URL [{cfg['adguard_url']}]: ").strip() or cfg["adguard_url"]
    cfg["adguard_username"] = input("AdGuard Home username: ").strip()
    cfg["adguard_password"] = input("AdGuard Home password: ").strip()
    router_ip = input("Router IP (leave blank to auto-detect): ").strip()
    if router_ip:
        cfg["router_ip"] = router_ip

    print("\n--- Notifications (all optional, press Enter to skip) ---")
    toast = input("Windows toast notifications? [Y/n]: ").strip().lower()
    cfg["notify_windows_toast"] = toast != "n"
    telegram_token = input("Telegram bot token (leave blank to skip): ").strip()
    if telegram_token:
        cfg["telegram_bot_token"] = telegram_token
        cfg["telegram_chat_id"] = input("Telegram chat id: ").strip()
        cfg["notify_telegram"] = True

    save(cfg)
    print(f"\nSaved to {CONFIG_PATH}. Edit that file directly any time.\n")
    return cfg


if __name__ == "__main__":
    run_first_time_setup()
