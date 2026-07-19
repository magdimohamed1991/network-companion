"""
notifier.py — Phase 2: turns device_events and quota crossings into actual alerts.

Two independent checks, each on its own cadence:
  1. New rows in device_events (new_device, watchdog_disarm, etc. — configurable via
     config.json's notify_event_types) since the last checkpoint.
  2. Every armed device with a monthly_quota_mb set, checked against
     quota_alert_thresholds (default 80% and 100%) — each (device, month, threshold)
     combo only ever fires once, tracked in quota_notifications.

Run continuously (registered as a 5th Scheduled Task, AtLogOn) or with --once for testing.
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import database
import notifications

CHECK_INTERVAL_SECONDS = 60


def check_events():
    cfg = config.load()
    watched_types = set(cfg.get("notify_event_types", []))
    if not watched_types:
        return

    last_id = int(database.get_notifier_state("last_notified_event_id", "0"))
    new_events = database.get_events_after(last_id)
    if not new_events:
        return

    devices = {d["mac"]: d for d in database.get_all_devices()}

    LABELS = {
        "new_device": ("New device", "joined your network"),
        "watchdog_disarm": ("Bandwidth tracking stopped", "no traffic detected — check arp_spoofer.py / IP forwarding"),
        "offline_disarm": ("Bandwidth tracking stopped", "device went offline"),
    }

    for event in new_events:
        if event["event_type"] in watched_types:
            dev = devices.get(event["mac"])
            name = (dev.get("friendly_name") or dev.get("hostname") or event["mac"]) if dev else event["mac"]
            title, suffix = LABELS.get(event["event_type"], (event["event_type"], ""))
            notifications.notify(title, f"{name} {suffix}".strip())
        database.set_notifier_state("last_notified_event_id", str(event["id"]))


def check_quota_thresholds():
    cfg = config.load()
    thresholds = sorted(cfg.get("quota_alert_thresholds", []))
    if not thresholds:
        return

    month_start = database.get_month_start_ts()
    for dev in database.get_all_devices():
        if not dev.get("monthly_quota_mb"):
            continue
        sent, received = database.get_usage_since(dev["mac"], month_start)
        usage_mb = (sent + received) / (1024 * 1024)
        pct = (usage_mb / dev["monthly_quota_mb"]) * 100

        for threshold in thresholds:
            if pct >= threshold and not database.has_notified_quota(dev["mac"], month_start, threshold):
                name = dev.get("friendly_name") or dev.get("hostname") or dev["mac"]
                label = "reached its monthly quota" if threshold >= 100 else f"passed {threshold}% of its monthly quota"
                notifications.notify(
                    "Quota alert",
                    f"{name} has {label} ({usage_mb:.0f} MB / {dev['monthly_quota_mb']} MB)",
                )
                database.mark_quota_notified(dev["mac"], month_start, threshold)


def run_once():
    database.init_db()
    check_events()
    check_quota_thresholds()


def main():
    parser = argparse.ArgumentParser(description="Watches device_events and quota usage, sends notifications")
    parser.add_argument("--once", action="store_true", help="Run a single check and exit")
    args = parser.parse_args()

    if args.once:
        run_once()
        return

    print(f"[i] Checking every {CHECK_INTERVAL_SECONDS}s. Ctrl+C to stop.")
    database.init_db()
    while True:
        try:
            check_events()
            check_quota_thresholds()
        except Exception as e:
            print(f"[!] Notifier check failed, will retry next cycle: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
