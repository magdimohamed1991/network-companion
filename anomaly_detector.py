"""
anomaly_detector.py — rule-based "Normal Behavior" profiling per device.

Runs continuously (or with --once for testing). Every CHECK_INTERVAL_SECONDS it:

  1. Measures each armed device's bandwidth over the last WINDOW_MINUTES.
  2. Compares it against that device's rolling baseline (exponential moving average of
     past windows, stored in the DB as a JSON blob in device_anomaly_profiles).
  3. Fires a high-priority Telegram / toast alert (and optionally auto-blocks the device)
     if any of these rules trigger:

     RULE_HIGH_UPLOAD  — upload in this window > baseline × SPIKE_FACTOR AND
                         absolute upload > MIN_SPIKE_MB (avoids false-positives on idle
                         devices where the baseline is nearly zero)
     RULE_NEW_MAC      — a brand-new device appeared (MAC never seen before)
     RULE_UNUSUAL_HOUR — armed device showing significant traffic during QUIET_HOURS
                         (configurable in config.json as anomaly_quiet_hours)

  4. Updates the baseline (EMA) for every device so "normal" naturally drifts over time
     as usage patterns change.

No ML library required — the EMA + spike-factor approach works well for home networks
where per-device traffic is highly predictable (a fridge doesn't suddenly upload 5 GB).
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import database
import notifications

CHECK_INTERVAL_SECONDS = 60
WINDOW_MINUTES = 15           # how much recent bandwidth to examine each cycle
SPIKE_FACTOR = 5.0            # >5× baseline triggers alert
MIN_SPIKE_MB = 50             # must also exceed this absolute threshold (avoids 0-baseline noise)
EMA_ALPHA = 0.1               # lower = slower-adapting baseline (more stable)
COOLDOWN_SECONDS = 1800       # don't re-alert the same device for the same rule within 30 min

# in-memory cooldown tracker: {(mac, rule): last_alerted_ts}
_cooldowns: dict[tuple, float] = {}


# ---------- DB helpers (schema added to database.py) ----------

def _get_profile(mac: str) -> dict:
    raw = database.get_notifier_state(f"anomaly_profile_{mac}", "{}")
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _save_profile(mac: str, profile: dict):
    database.set_notifier_state(f"anomaly_profile_{mac}", json.dumps(profile))


# ---------- Core logic ----------

def _in_cooldown(mac: str, rule: str) -> bool:
    key = (mac, rule)
    last = _cooldowns.get(key, 0)
    return (time.time() - last) < COOLDOWN_SECONDS


def _mark_cooldown(mac: str, rule: str):
    _cooldowns[(mac, rule)] = time.time()


def _alert(title: str, message: str, mac: str, rule: str, auto_block: bool = False):
    if _in_cooldown(mac, rule):
        return
    _mark_cooldown(mac, rule)
    print(f"[!] ANOMALY [{rule}] {title}: {message}")
    notifications.notify(f"⚠️ {title}", message)
    if auto_block:
        database.set_quota_action(mac, "block")
        notifications.notify("🔒 Auto-blocked", f"{message} — device has been blocked pending review.")
        print(f"[!] Auto-blocked {mac} due to anomaly rule {rule}")


def check_bandwidth_anomalies():
    cfg = config.load()
    auto_block_rules = set(cfg.get("anomaly_auto_block_rules", []))
    quiet_hours: list = cfg.get("anomaly_quiet_hours", [])  # e.g. [{"start": 1, "end": 6}]
    min_spike_mb = cfg.get("anomaly_min_spike_mb", MIN_SPIKE_MB)
    spike_factor = cfg.get("anomaly_spike_factor", SPIKE_FACTOR)

    now_hour = datetime.now().hour
    in_quiet = any(
        (qh["start"] <= now_hour < qh["end"])
        if qh["start"] <= qh["end"]
        else (now_hour >= qh["start"] or now_hour < qh["end"])
        for qh in quiet_hours
    )

    window_start = time.time() - WINDOW_MINUTES * 60
    armed = database.get_armed_devices()
    devices_map = {d["mac"]: d for d in database.get_all_devices()}

    for dev in armed:
        mac = dev["mac"]
        label = dev.get("friendly_name") or dev.get("hostname") or mac
        sent, received = database.get_usage_since(mac, window_start)
        upload_mb = sent / (1024 * 1024)
        download_mb = received / (1024 * 1024)
        total_mb = upload_mb + download_mb

        profile = _get_profile(mac)
        baseline_upload = profile.get("baseline_upload_mb", upload_mb)
        baseline_total = profile.get("baseline_total_mb", total_mb)

        # --- RULE: High upload spike ---
        if (
            baseline_upload > 0
            and upload_mb > baseline_upload * spike_factor
            and upload_mb > min_spike_mb
        ):
            rule = "RULE_HIGH_UPLOAD"
            _alert(
                "Unusual upload spike",
                f"{label} uploaded {upload_mb:.1f} MB in {WINDOW_MINUTES} min "
                f"(baseline: {baseline_upload:.1f} MB)",
                mac, rule,
                auto_block="RULE_HIGH_UPLOAD" in auto_block_rules,
            )

        # --- RULE: Significant traffic during quiet hours ---
        if in_quiet and total_mb > min_spike_mb:
            rule = "RULE_UNUSUAL_HOUR"
            _alert(
                "Night-time traffic detected",
                f"{label} used {total_mb:.1f} MB during quiet hours (hour {now_hour}:00)",
                mac, rule,
                auto_block="RULE_UNUSUAL_HOUR" in auto_block_rules,
            )

        # --- RULE: High total bandwidth (regardless of time) ---
        if (
            baseline_total > 0
            and total_mb > baseline_total * spike_factor
            and total_mb > min_spike_mb
        ):
            rule = "RULE_HIGH_TOTAL"
            _alert(
                "Unusual total bandwidth",
                f"{label} used {total_mb:.1f} MB in {WINDOW_MINUTES} min "
                f"(baseline: {baseline_total:.1f} MB)",
                mac, rule,
                auto_block="RULE_HIGH_TOTAL" in auto_block_rules,
            )

        # Update EMA baseline (only when not in a spike, to avoid poisoning the baseline)
        if upload_mb <= baseline_upload * spike_factor:
            profile["baseline_upload_mb"] = round(
                EMA_ALPHA * upload_mb + (1 - EMA_ALPHA) * baseline_upload, 4
            )
        if total_mb <= baseline_total * spike_factor:
            profile["baseline_total_mb"] = round(
                EMA_ALPHA * total_mb + (1 - EMA_ALPHA) * baseline_total, 4
            )
        _save_profile(mac, profile)


def check_new_mac_anomaly():
    """Alert on brand-new devices (supplementing the regular notifier.py new_device event
    but with higher priority / dedicated anomaly framing)."""
    cfg = config.load()
    if not cfg.get("anomaly_alert_new_mac", True):
        return

    auto_block = "RULE_NEW_MAC" in set(cfg.get("anomaly_auto_block_rules", []))
    last_id = int(database.get_notifier_state("anomaly_last_event_id", "0"))
    new_events = database.get_events_after(last_id, limit=100)
    if not new_events:
        return

    devices_map = {d["mac"]: d for d in database.get_all_devices()}
    max_id = last_id
    for event in new_events:
        max_id = max(max_id, event["id"])
        if event["event_type"] != "new_device":
            continue
        mac = event["mac"]
        dev = devices_map.get(mac, {})
        label = dev.get("friendly_name") or dev.get("hostname") or mac
        vendor = dev.get("vendor") or "unknown vendor"
        ip = dev.get("ip") or "unknown IP"
        _alert(
            "New device joined network",
            f"{label} ({vendor}) at {ip} — MAC {mac}",
            mac, "RULE_NEW_MAC",
            auto_block=auto_block,
        )

    database.set_notifier_state("anomaly_last_event_id", str(max_id))


def run_once():
    database.init_db()
    check_new_mac_anomaly()
    check_bandwidth_anomalies()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Rule-based anomaly detection for network devices")
    parser.add_argument("--once", action="store_true", help="Run a single check and exit")
    args = parser.parse_args()

    if args.once:
        run_once()
        return

    print(f"[i] Anomaly detector running, checking every {CHECK_INTERVAL_SECONDS}s. Ctrl+C to stop.")
    database.init_db()
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[!] Anomaly check failed, will retry: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
