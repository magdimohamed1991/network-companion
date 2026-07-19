"""
speedtest_runner.py — scheduled speed test integration for Network Companion.

Runs a speedtest-cli test on demand or on a schedule and stores results in the DB.
Typically triggered via the dashboard's "Run Speed Test" button (which calls the API),
or can be run from the command line for testing.

Requires:  pip install speedtest-cli
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import database


def run_speedtest() -> dict:
    """Run a single speed test and return the result dict. Raises on failure."""
    try:
        import speedtest as st_lib
    except ImportError:
        raise RuntimeError("speedtest-cli is not installed. Run: pip install speedtest-cli")

    print("[i] Running speed test (this takes ~15-30 seconds)...")
    started = time.time()

    s = st_lib.Speedtest(secure=True)
    s.get_best_server()
    s.download(threads=4)
    s.upload(threads=4, pre_allocate=False)
    results = s.results.dict()

    result = {
        "at": started,
        "ping_ms": round(results.get("ping", 0), 2),
        "download_mbps": round(results.get("download", 0) / 1_000_000, 2),
        "upload_mbps": round(results.get("upload", 0) / 1_000_000, 2),
        "server_name": results.get("server", {}).get("name", ""),
        "server_host": results.get("server", {}).get("host", ""),
        "isp": results.get("client", {}).get("isp", ""),
    }

    database.record_speedtest_result(
        result["at"],
        result["ping_ms"],
        result["download_mbps"],
        result["upload_mbps"],
        result["server_name"],
        result["server_host"],
        result["isp"],
    )

    elapsed = time.time() - started
    print(
        f"[+] Speed test done in {elapsed:.0f}s: "
        f"↓{result['download_mbps']} Mbps  ↑{result['upload_mbps']} Mbps  "
        f"ping {result['ping_ms']} ms  ({result['isp']})"
    )
    return result


def main():
    parser = argparse.ArgumentParser(description="Run a speed test and store the result")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--loop-hours", type=float, default=None,
                        help="Run every N hours continuously (e.g. 6 for 4× per day)")
    args = parser.parse_args()

    database.init_db()

    if args.loop_hours:
        print(f"[i] Running speed test every {args.loop_hours}h. Ctrl+C to stop.")
        while True:
            try:
                run_speedtest()
            except Exception as e:
                print(f"[!] Speed test failed: {e}")
            time.sleep(args.loop_hours * 3600)
    else:
        # Default: run once
        try:
            run_speedtest()
        except Exception as e:
            print(f"[!] Speed test failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
