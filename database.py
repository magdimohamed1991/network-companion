"""
database.py — shared SQLite layer for Network Companion.

Both scanner.py (writer) and the dashboard backend (reader/writer) import
this module so there is exactly one schema definition and one place that
knows how to talk to the DB file.

The DB file lives next to this script by default: network_companion.db
"""

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "network_companion.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac             TEXT PRIMARY KEY,
    ip              TEXT,
    ipv6            TEXT,
    hostname        TEXT,
    vendor          TEXT,
    friendly_name   TEXT,
    tags            TEXT,             -- Phase 4: comma-separated tags
    is_known        INTEGER NOT NULL DEFAULT 0,
    monthly_quota_mb INTEGER,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    is_online       INTEGER NOT NULL DEFAULT 1,
    bandwidth_armed INTEGER NOT NULL DEFAULT 0,   -- opt-in: only armed devices get ARP-spoofed for bandwidth capture
    armed_at        REAL,
    router_ip       TEXT,
    -- Phase 3: what to do once monthly_quota_mb is exceeded. 'none' = just show it in the
    -- dashboard (Phase 1/2 behavior). 'throttle'/'block' require the relay (see arp_spoofer.py).
    quota_action        TEXT NOT NULL DEFAULT 'none',   -- 'none' | 'throttle' | 'block'
    throttle_rate_kbps  INTEGER
);

-- Phase 3: scheduled access windows (e.g. "block 10pm-7am"). A device can have multiple
-- rules; if ANY enabled rule's window is currently active, that rule's action applies.
-- Combined with quota_action to get the single effective action (see get_effective_policy)
-- — whichever of the two is more restrictive wins.
CREATE TABLE IF NOT EXISTS schedule_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL,
    label           TEXT,
    days_of_week    TEXT NOT NULL,     -- comma-separated 0-6, 0=Sunday
    start_minute    INTEGER NOT NULL,  -- minutes since midnight, local time
    end_minute      INTEGER NOT NULL,  -- if end < start, window wraps past midnight
    action          TEXT NOT NULL DEFAULT 'block',  -- 'block' | 'throttle'
    throttle_rate_kbps INTEGER,
    enabled         INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_schedule_mac ON schedule_rules(mac);

CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL,
    at              REAL NOT NULL,
    bytes_sent      INTEGER NOT NULL,      -- delta since previous sample, not cumulative
    bytes_received  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bw_mac_at ON bandwidth_samples(mac, at);

-- Rolled-up hourly totals. maintenance.py moves samples older than ROLLUP_AFTER_HOURS
-- here (summed per hour) and deletes the raw rows, so the DB doesn't grow unbounded
-- while monthly/quota totals stay accurate indefinitely.
CREATE TABLE IF NOT EXISTS bandwidth_hourly (
    mac             TEXT NOT NULL,
    hour_start      REAL NOT NULL,     -- unix ts, truncated to the top of the hour
    bytes_sent      INTEGER NOT NULL,
    bytes_received  INTEGER NOT NULL,
    PRIMARY KEY (mac, hour_start)
);

CREATE INDEX IF NOT EXISTS idx_bwh_mac_hour ON bandwidth_hourly(mac, hour_start);

CREATE TABLE IF NOT EXISTS spoof_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL,
    action          TEXT NOT NULL,     -- 'armed' | 'disarmed' | 'restored' | 'error'
    detail          TEXT,
    at              REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      REAL NOT NULL,
    finished_at     REAL,
    devices_found   INTEGER,
    subnet          TEXT
);

CREATE TABLE IF NOT EXISTS device_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL,
    event_type      TEXT NOT NULL,   -- 'new_device' | 'online' | 'offline' | 'watchdog_disarm'
    at              REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_mac ON device_events(mac);

-- Phase 2: notifications. notifier_state is a small checkpoint store (e.g. "last event id
-- we've already notified about") so notifier.py doesn't re-send on every poll. 
-- quota_notifications records which (device, month, threshold%) combos already fired, so
-- crossing 80% notifies once, not on every subsequent poll for the rest of the month.
CREATE TABLE IF NOT EXISTS notifier_state (
    key             TEXT PRIMARY KEY,
    value           TEXT
);

CREATE TABLE IF NOT EXISTS quota_notifications (
    mac             TEXT NOT NULL,
    month_start     REAL NOT NULL,
    threshold_pct   INTEGER NOT NULL,
    notified_at     REAL NOT NULL,
    PRIMARY KEY (mac, month_start, threshold_pct)
);

-- Phase 4: router SNMP bandwidth monitoring
CREATE TABLE IF NOT EXISTS router_bandwidth_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              REAL NOT NULL,
    bytes_sent      INTEGER NOT NULL,
    bytes_received  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_router_bw_at ON router_bandwidth_samples(at);

CREATE TABLE IF NOT EXISTS router_bandwidth_hourly (
    hour_start      REAL PRIMARY KEY,
    bytes_sent      INTEGER NOT NULL,
    bytes_received  INTEGER NOT NULL
);

-- Feature: Speed test results
CREATE TABLE IF NOT EXISTS speedtest_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              REAL NOT NULL,
    ping_ms         REAL NOT NULL,
    download_mbps   REAL NOT NULL,
    upload_mbps     REAL NOT NULL,
    server_name     TEXT,
    server_host     TEXT,
    isp             TEXT
);

CREATE INDEX IF NOT EXISTS idx_speedtest_at ON speedtest_results(at);

-- Feature: Auth users (multi-role dashboard access)
CREATE TABLE IF NOT EXISTS auth_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,   -- bcrypt hash
    role            TEXT NOT NULL DEFAULT 'viewer',  -- 'admin' | 'viewer'
    created_at      REAL NOT NULL
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # let scanner + dashboard read/write concurrently
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def upsert_device(mac: str, ip: str, ipv6: str | None, hostname: str | None, vendor: str | None):
    """Insert a newly-seen device or refresh an existing one. Returns True if this is a brand-new device."""
    now = time.time()
    with get_conn() as conn:
        row = conn.execute("SELECT mac, is_online FROM devices WHERE mac = ?", (mac,)).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO devices (mac, ip, ipv6, hostname, vendor, friendly_name, is_known,
                                         first_seen, last_seen, is_online)
                   VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 1)""",
                (mac, ip, ipv6, hostname, vendor, hostname or vendor or mac, now, now),
            )
            conn.execute(
                "INSERT INTO device_events (mac, event_type, at) VALUES (?, 'new_device', ?)",
                (mac, now),
            )
            return True
        else:
            was_offline = row["is_online"] == 0
            conn.execute(
                """UPDATE devices SET ip = ?, ipv6 = COALESCE(?, ipv6), last_seen = ?, is_online = 1,
                   hostname = COALESCE(?, hostname), vendor = COALESCE(?, vendor)
                   WHERE mac = ?""",
                (ip, ipv6, now, hostname, vendor, mac),
            )
            if was_offline:
                conn.execute(
                    "INSERT INTO device_events (mac, event_type, at) VALUES (?, 'online', ?)",
                    (mac, now),
                )
            return False


def mark_stale_devices_offline(seen_macs: set[str], offline_after_seconds: int = 300):
    """Any device not seen in this scan (and not seen recently) gets flagged offline."""
    now = time.time()
    cutoff = now - offline_after_seconds
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT mac FROM devices WHERE is_online = 1 AND last_seen < ?", (cutoff,)
        ).fetchall()
        for row in rows:
            if row["mac"] not in seen_macs:
                conn.execute("UPDATE devices SET is_online = 0 WHERE mac = ?", (row["mac"],))
                conn.execute(
                    "INSERT INTO device_events (mac, event_type, at) VALUES (?, 'offline', ?)",
                    (row["mac"], now),
                )


def log_scan(started_at: float, finished_at: float, devices_found: int, subnet: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scan_log (started_at, finished_at, devices_found, subnet)
               VALUES (?, ?, ?, ?)""",
            (started_at, finished_at, devices_found, subnet),
        )


def get_all_devices():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()]


def set_device_name(mac: str, friendly_name: str):
    with get_conn() as conn:
        conn.execute("UPDATE devices SET friendly_name = ?, is_known = 1 WHERE mac = ?", (friendly_name, mac))


def set_device_tags(mac: str, tags: str | None):
    with get_conn() as conn:
        conn.execute("UPDATE devices SET tags = ? WHERE mac = ?", (tags, mac))


def set_device_quota(mac: str, quota_mb: int | None):
    with get_conn() as conn:
        conn.execute("UPDATE devices SET monthly_quota_mb = ? WHERE mac = ?", (quota_mb, mac))


def arm_bandwidth_capture(mac: str, router_ip: str):
    """Opt a device into ARP-spoof-based bandwidth capture. Only armed devices get spoofed."""
    now = time.time()
    with get_conn() as conn:
        conn.execute(
            "UPDATE devices SET bandwidth_armed = 1, armed_at = ?, router_ip = ? WHERE mac = ?",
            (now, router_ip, mac),
        )
        conn.execute(
            "INSERT INTO spoof_log (mac, action, detail, at) VALUES (?, 'armed', ?, ?)",
            (mac, f"router_ip={router_ip}", now),
        )


def disarm_bandwidth_capture(mac: str, detail: str = ""):
    now = time.time()
    with get_conn() as conn:
        conn.execute("UPDATE devices SET bandwidth_armed = 0 WHERE mac = ?", (mac,))
        conn.execute(
            "INSERT INTO spoof_log (mac, action, detail, at) VALUES (?, 'disarmed', ?, ?)",
            (mac, detail, now),
        )


def get_armed_devices():
    """Devices the user has explicitly opted in to bandwidth capture. arp_spoofer.py only touches these."""
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM devices WHERE bandwidth_armed = 1"
            ).fetchall()
        ]


def record_bandwidth_sample(mac: str, bytes_sent: int, bytes_received: int):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO bandwidth_samples (mac, at, bytes_sent, bytes_received) VALUES (?, ?, ?, ?)",
            (mac, time.time(), bytes_sent, bytes_received),
        )


def get_usage_since(mac: str, since_ts: float):
    """Sum of bandwidth for one device since a given unix timestamp. Returns (sent_bytes, received_bytes).

    Sums BOTH bandwidth_samples (recent, not yet rolled up) and bandwidth_hourly (older,
    archived by maintenance.py) — without the second half, monthly/quota totals would
    silently drop once maintenance.py starts archiving samples older than ~48h.
    """
    with get_conn() as conn:
        raw = conn.execute(
            """SELECT COALESCE(SUM(bytes_sent), 0) AS sent, COALESCE(SUM(bytes_received), 0) AS recv
               FROM bandwidth_samples WHERE mac = ? AND at >= ?""",
            (mac, since_ts),
        ).fetchone()
        rolled = conn.execute(
            """SELECT COALESCE(SUM(bytes_sent), 0) AS sent, COALESCE(SUM(bytes_received), 0) AS recv
               FROM bandwidth_hourly WHERE mac = ? AND hour_start >= ?""",
            (mac, since_ts),
        ).fetchone()
        return raw["sent"] + rolled["sent"], raw["recv"] + rolled["recv"]


def get_hourly_history(mac: str, since_ts: float):
    """Hourly bandwidth series for trend charts — merges rolled-up hours with the current
    (not-yet-rolled-up) partial hour so charts don't have a gap for the last ~48h."""
    with get_conn() as conn:
        hourly = [
            dict(r)
            for r in conn.execute(
                "SELECT hour_start, bytes_sent, bytes_received FROM bandwidth_hourly WHERE mac = ? AND hour_start >= ? ORDER BY hour_start",
                (mac, since_ts),
            ).fetchall()
        ]
        raw = conn.execute(
            "SELECT at, bytes_sent, bytes_received FROM bandwidth_samples WHERE mac = ? AND at >= ? ORDER BY at",
            (mac, max(since_ts, hourly[-1]["hour_start"] + 3600 if hourly else since_ts)),
        ).fetchall()

    # Bucket the still-raw samples into hours too, so recent data has the same shape
    buckets: dict[float, dict] = {}
    for r in raw:
        bucket = r["at"] - (r["at"] % 3600)
        b = buckets.setdefault(bucket, {"hour_start": bucket, "bytes_sent": 0, "bytes_received": 0})
        b["bytes_sent"] += r["bytes_sent"]
        b["bytes_received"] += r["bytes_received"]

    return sorted(hourly + list(buckets.values()), key=lambda x: x["hour_start"])


def rollup_bandwidth_samples(older_than_hours: int = 48) -> int:
    """Aggregate bandwidth_samples older than the cutoff into bandwidth_hourly, then delete
    the raw rows. Returns the number of raw rows rolled up. Safe to call repeatedly/often —
    it's a no-op once there's nothing old enough to roll up."""
    cutoff = time.time() - older_than_hours * 3600
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, mac, at, bytes_sent, bytes_received FROM bandwidth_samples WHERE at < ?",
            (cutoff,),
        ).fetchall()
        if not rows:
            return 0

        hourly_sums: dict[tuple, dict] = {}
        ids_to_delete = []
        for r in rows:
            hour_start = r["at"] - (r["at"] % 3600)
            key = (r["mac"], hour_start)
            bucket = hourly_sums.setdefault(key, {"sent": 0, "recv": 0})
            bucket["sent"] += r["bytes_sent"]
            bucket["recv"] += r["bytes_received"]
            ids_to_delete.append(r["id"])

        for (mac, hour_start), totals in hourly_sums.items():
            conn.execute(
                """INSERT INTO bandwidth_hourly (mac, hour_start, bytes_sent, bytes_received)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(mac, hour_start) DO UPDATE SET
                       bytes_sent = bytes_sent + excluded.bytes_sent,
                       bytes_received = bytes_received + excluded.bytes_received""",
                (mac, hour_start, totals["sent"], totals["recv"]),
            )

        conn.executemany("DELETE FROM bandwidth_samples WHERE id = ?", [(i,) for i in ids_to_delete])
        return len(ids_to_delete)


def prune_scan_log(keep_days: int = 30) -> int:
    cutoff = time.time() - keep_days * 86400
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scan_log WHERE started_at < ?", (cutoff,))
        return cur.rowcount


def prune_device_events(keep_days: int = 90) -> int:
    cutoff = time.time() - keep_days * 86400
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM device_events WHERE at < ?", (cutoff,))
        return cur.rowcount


def prune_spoof_log(keep_days: int = 90) -> int:
    cutoff = time.time() - keep_days * 86400
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM spoof_log WHERE at < ?", (cutoff,))
        return cur.rowcount


def set_quota_action(mac: str, action: str, throttle_rate_kbps: int | None = None):
    if action not in ("none", "throttle", "block"):
        raise ValueError(f"invalid quota_action: {action}")
    with get_conn() as conn:
        conn.execute(
            "UPDATE devices SET quota_action = ?, throttle_rate_kbps = ? WHERE mac = ?",
            (action, throttle_rate_kbps, mac),
        )


def add_schedule_rule(mac: str, label: str, days_of_week: str, start_minute: int, end_minute: int,
                       action: str = "block", throttle_rate_kbps: int | None = None) -> int:
    if action not in ("block", "throttle"):
        raise ValueError(f"invalid schedule action: {action}")
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO schedule_rules (mac, label, days_of_week, start_minute, end_minute, action, throttle_rate_kbps, enabled)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
            (mac, label, days_of_week, start_minute, end_minute, action, throttle_rate_kbps),
        )
        return cur.lastrowid


def remove_schedule_rule(rule_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM schedule_rules WHERE id = ?", (rule_id,))


def set_schedule_rule_enabled(rule_id: int, enabled: bool):
    with get_conn() as conn:
        conn.execute("UPDATE schedule_rules SET enabled = ? WHERE id = ?", (1 if enabled else 0, rule_id))


def list_schedule_rules(mac: str):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM schedule_rules WHERE mac = ? ORDER BY id", (mac,)).fetchall()]


_ACTION_RANK = {"none": 0, "throttle": 1, "block": 2}  # higher = more restrictive


def get_effective_policy(mac: str, now=None) -> dict:
    """The single source of truth for what should happen to this device's traffic right
    now: {'action': 'none'|'throttle'|'block', 'throttle_rate_kbps': int|None, 'reason': str}.

    Combines quota status and any active schedule window; whichever is more restrictive
    wins (block > throttle > none). Used by arp_spoofer.py's relay on every packet, and by
    the dashboard to show *why* a device is currently restricted.
    """
    import datetime
    now = now or datetime.datetime.now()

    with get_conn() as conn:
        dev = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if dev is None:
        return {"action": "none", "throttle_rate_kbps": None, "reason": "unknown device"}

    best = {"action": "none", "throttle_rate_kbps": None, "reason": "no restriction"}

    # --- Quota check ---
    if dev["quota_action"] != "none" and dev["monthly_quota_mb"]:
        month_start = get_month_start_ts()
        sent, received = get_usage_since(mac, month_start)
        usage_mb = (sent + received) / (1024 * 1024)
        if usage_mb >= dev["monthly_quota_mb"]:
            candidate = {
                "action": dev["quota_action"],
                "throttle_rate_kbps": dev["throttle_rate_kbps"],
                "reason": f"over monthly quota ({usage_mb:.0f}/{dev['monthly_quota_mb']} MB)",
            }
            if _ACTION_RANK[candidate["action"]] > _ACTION_RANK[best["action"]]:
                best = candidate

    # --- Schedule check ---
    current_minute = now.hour * 60 + now.minute
    current_dow = (now.weekday() + 1) % 7       # datetime: Mon=0..Sun=6 -> our 0=Sunday..6=Saturday
    yesterday_dow = (current_dow - 1) % 7

    for rule in list_schedule_rules(mac):
        if not rule["enabled"]:
            continue

        start, end = rule["start_minute"], rule["end_minute"]
        rule_days = rule["days_of_week"].split(",")

        if start <= end:
            # Same-day window (e.g. 08:00-17:00) — only checked against today's day-of-week.
            in_window = str(current_dow) in rule_days and start <= current_minute < end
        else:
            # Wraps midnight (e.g. 22:00-07:00): the late-night part belongs to a day in
            # rule_days, but the early-morning part after midnight is calendar-today even
            # though it's conceptually "last night" — so check BOTH:
            #   - today is a rule day AND we're past the start (the late-night part), or
            #   - yesterday was a rule day AND we're before the end (the early-morning part)
            in_window = (str(current_dow) in rule_days and current_minute >= start) or \
                        (str(yesterday_dow) in rule_days and current_minute < end)

        if not in_window:
            continue

        candidate = {
            "action": rule["action"],
            "throttle_rate_kbps": rule["throttle_rate_kbps"],
            "reason": f"scheduled restriction: {rule['label'] or 'unnamed rule'}",
        }
        if _ACTION_RANK[candidate["action"]] > _ACTION_RANK[best["action"]]:
            best = candidate
        elif candidate["action"] == best["action"] == "throttle":
            # both throttling — the lower (more restrictive) rate wins
            rates = [r for r in (candidate["throttle_rate_kbps"], best["throttle_rate_kbps"]) if r]
            if rates:
                best["throttle_rate_kbps"] = min(rates)

    return best


def disarm_all_devices(detail: str = "emergency unblock") -> int:
    """Kill switch: disarm every currently-armed device at once. arp_spoofer.py picks this
    up on its next cycle and restores real ARP for all of them — the most complete way to
    guarantee full connectivity is restored, since it removes this system from the traffic
    path entirely rather than depending on policy logic to behave."""
    armed = get_armed_devices()
    for dev in armed:
        disarm_bandwidth_capture(dev["mac"], detail=detail)
    return len(armed)


def get_month_start_ts():
    import datetime

    now = datetime.datetime.now()
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start.timestamp()


def log_spoof_event(mac: str, action: str, detail: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO spoof_log (mac, action, detail, at) VALUES (?, ?, ?, ?)",
            (mac, action, detail, time.time()),
        )


def log_device_event(mac: str, event_type: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO device_events (mac, event_type, at) VALUES (?, ?, ?)",
            (mac, event_type, time.time()),
        )


def get_events_after(event_id: int, limit: int = 100):
    """New device_events since a checkpoint id — what notifier.py sends alerts for."""
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM device_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (event_id, limit),
            ).fetchall()
        ]


def get_notifier_state(key: str, default: str | None = None) -> str | None:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM notifier_state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_notifier_state(key: str, value: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO notifier_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def has_notified_quota(mac: str, month_start: float, threshold_pct: int) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM quota_notifications WHERE mac = ? AND month_start = ? AND threshold_pct = ?",
            (mac, month_start, threshold_pct),
        ).fetchone()
        return row is not None


def mark_quota_notified(mac: str, month_start: float, threshold_pct: int):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO quota_notifications (mac, month_start, threshold_pct, notified_at)
               VALUES (?, ?, ?, ?) ON CONFLICT(mac, month_start, threshold_pct) DO NOTHING""",
            (mac, month_start, threshold_pct, time.time()),
        )


def get_recent_events(limit: int = 50):
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM device_events ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
        ]


def record_router_bandwidth_sample(bytes_sent: int, bytes_received: int):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO router_bandwidth_samples (at, bytes_sent, bytes_received) VALUES (?, ?, ?)",
            (time.time(), bytes_sent, bytes_received),
        )


def get_router_usage_since(since_ts: float):
    with get_conn() as conn:
        raw = conn.execute(
            """SELECT COALESCE(SUM(bytes_sent), 0) AS sent, COALESCE(SUM(bytes_received), 0) AS recv
               FROM router_bandwidth_samples WHERE at >= ?""",
            (since_ts,),
        ).fetchone()
        rolled = conn.execute(
            """SELECT COALESCE(SUM(bytes_sent), 0) AS sent, COALESCE(SUM(bytes_received), 0) AS recv
               FROM router_bandwidth_hourly WHERE hour_start >= ?""",
            (since_ts,),
        ).fetchone()
        return raw["sent"] + rolled["sent"], raw["recv"] + rolled["recv"]


# ---------- Speed test ----------

def record_speedtest_result(at: float, ping_ms: float, download_mbps: float, upload_mbps: float,
                             server_name: str, server_host: str, isp: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO speedtest_results (at, ping_ms, download_mbps, upload_mbps, server_name, server_host, isp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (at, ping_ms, download_mbps, upload_mbps, server_name, server_host, isp),
        )


def get_speedtest_history(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM speedtest_results ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
        ]


def get_latest_speedtest() -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM speedtest_results ORDER BY at DESC LIMIT 1").fetchone()
        return dict(row) if row else None


# ---------- Auth users ----------

def get_user_by_username(username: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM auth_users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_all_users() -> list[dict]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT id, username, role, created_at FROM auth_users").fetchall()]


def create_user(username: str, password_hash: str, role: str = "viewer") -> int:
    if role not in ("admin", "viewer"):
        raise ValueError(f"invalid role: {role}")
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO auth_users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, time.time()),
        )
        return cur.lastrowid


def update_user_password(username: str, password_hash: str):
    with get_conn() as conn:
        conn.execute("UPDATE auth_users SET password_hash = ? WHERE username = ?", (password_hash, username))


def delete_user(username: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM auth_users WHERE username = ?", (username,))


def count_admins() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) as c FROM auth_users WHERE role = 'admin'").fetchone()
        return row["c"]


# ---------- Topology helpers ----------

def get_topology_data() -> dict:
    """Return devices + connection hints for the topology map.
    Since we don't have L2 topology from the scanner, we infer:
      - router node (default gateway)
      - all devices connected to router
    The UI can distinguish connection type via vendor hints."""
    with get_conn() as conn:
        devices = [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()]
    return {"devices": devices}


def rollup_router_bandwidth_samples(older_than_hours: int = 48) -> int:
    cutoff = time.time() - older_than_hours * 3600
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, at, bytes_sent, bytes_received FROM router_bandwidth_samples WHERE at < ?",
            (cutoff,),
        ).fetchall()
        if not rows:
            return 0

        hourly_sums: dict[float, dict] = {}
        ids_to_delete = []
        for r in rows:
            hour_start = r["at"] - (r["at"] % 3600)
            bucket = hourly_sums.setdefault(hour_start, {"sent": 0, "recv": 0})
            bucket["sent"] += r["bytes_sent"]
            bucket["recv"] += r["bytes_received"]
            ids_to_delete.append(r["id"])

        for hour_start, totals in hourly_sums.items():
            conn.execute(
                """INSERT INTO router_bandwidth_hourly (hour_start, bytes_sent, bytes_received)
                   VALUES (?, ?, ?)
                   ON CONFLICT(hour_start) DO UPDATE SET
                       bytes_sent = bytes_sent + excluded.bytes_sent,
                       received = bytes_received + excluded.bytes_received""",
                (hour_start, totals["sent"], totals["recv"]),
            )

        conn.executemany("DELETE FROM router_bandwidth_samples WHERE id = ?", [(i,) for i in ids_to_delete])
        return len(ids_to_delete)
