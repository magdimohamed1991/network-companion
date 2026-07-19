"""
maintenance.py — Phase 1: data retention.

Without this, bandwidth_samples grows forever — at a 10s sample interval that's roughly
8,600 rows per armed device per day. This rolls anything older than ROLLUP_AFTER_HOURS
into hourly totals (bandwidth_hourly) and deletes the raw rows, and prunes old scan_log /
device_events / spoof_log rows that have no long-term value.

Run daily via Task Scheduler (see install/register_tasks.ps1, which adds this as a
fourth task with a daily trigger instead of AtLogOn) or manually with --once.
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import database

ROLLUP_AFTER_HOURS = 48
KEEP_SCAN_LOG_DAYS = 30
KEEP_DEVICE_EVENTS_DAYS = 90
KEEP_SPOOF_LOG_DAYS = 90


def run_once():
    database.init_db()
    started = time.time()

    rolled = database.rollup_bandwidth_samples(older_than_hours=ROLLUP_AFTER_HOURS)
    scan_pruned = database.prune_scan_log(keep_days=KEEP_SCAN_LOG_DAYS)
    events_pruned = database.prune_device_events(keep_days=KEEP_DEVICE_EVENTS_DAYS)
    spoof_pruned = database.prune_spoof_log(keep_days=KEEP_SPOOF_LOG_DAYS)

    with database.get_conn() as conn:
        db_size_mb = Path(database.DB_PATH).stat().st_size / (1024 * 1024)

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Maintenance complete in {time.time() - started:.1f}s")
    print(f"  Rolled up {rolled} raw bandwidth samples into hourly totals")
    print(f"  Pruned {scan_pruned} scan_log rows (>{KEEP_SCAN_LOG_DAYS}d old)")
    print(f"  Pruned {events_pruned} device_events rows (>{KEEP_DEVICE_EVENTS_DAYS}d old)")
    print(f"  Pruned {spoof_pruned} spoof_log rows (>{KEEP_SPOOF_LOG_DAYS}d old)")
    print(f"  Database size: {db_size_mb:.2f} MB")


def main():
    parser = argparse.ArgumentParser(description="Data retention: rollup + pruning")
    parser.add_argument("--once", action="store_true", help="Run once and exit (used by the daily Scheduled Task)")
    parser.add_argument("--loop-hours", type=float, default=None, help="Instead of exiting, repeat every N hours (for manual/foreground use)")
    args = parser.parse_args()

    if args.loop_hours:
        print(f"[i] Running maintenance every {args.loop_hours}h. Ctrl+C to stop.")
        while True:
            try:
                run_once()
            except Exception as e:
                print(f"[!] Maintenance run failed, will retry next cycle: {e}")
            time.sleep(args.loop_hours * 3600)
    else:
        run_once()


if __name__ == "__main__":
    main()
