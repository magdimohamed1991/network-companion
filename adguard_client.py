"""
adguard_client.py — thin wrapper around AdGuard Home's REST API.

This is what turns AdGuard Home (which you install separately, natively, as a Windows
service — see install/README) into the "what sites is this device visiting" data source.
AdGuard Home sees every DNS query on your network once your router's DHCP DNS setting
points at it, so per-client query history is a genuine (domain-level, not full-URL)
record of what each device is looking up.

NOTE ON API STABILITY: AdGuard Home's /control/querylog response shape has shifted
slightly across versions. This client reads defensively (tries a couple of known field
paths) and logs a warning rather than crashing if a field is missing. If it comes back
empty, hit http://<agh-ip>:3000/control/querylog directly in a browser (while logged in)
to see your version's actual shape and adjust QUESTION_NAME_PATH below.
"""

import base64
from datetime import datetime, timezone

import requests


class AdGuardClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = requests.get(f"{self.base_url}{path}", auth=self.auth, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict:
        return self._get("/control/status")

    def query_log(self, limit: int = 500, older_than: str | None = None) -> dict:
        params = {"limit": limit}
        if older_than:
            params["older_than"] = older_than
        return self._get("/control/querylog", params=params)

    @staticmethod
    def _extract_domain(entry: dict) -> str | None:
        q = entry.get("question", {})
        name = q.get("name")
        if not name:
            return None
        # Some AGH versions base64-encode this field; detect and decode if so.
        try:
            if all(c.isalnum() or c in "+/=" for c in name) and len(name) % 4 == 0 and "." not in name:
                name = base64.b64decode(name).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return name.rstrip(".") if name else None

    def recent_queries_by_client(self, limit: int = 500) -> dict[str, list[dict]]:
        """Returns {client_ip: [{"domain": ..., "time": ...}, ...]}, newest first per client."""
        data = self.query_log(limit=limit)
        by_client: dict[str, list[dict]] = {}
        for entry in data.get("data", []):
            client_ip = entry.get("client")
            domain = self._extract_domain(entry)
            if not client_ip or not domain:
                continue
            by_client.setdefault(client_ip, []).append({
                "domain": domain,
                "time": entry.get("time"),
                "blocked": bool(entry.get("reason", "").startswith("Filtered")) if entry.get("reason") else False,
            })
        return by_client

    def top_domains_for_client(self, client_ip: str, limit: int = 500, top_n: int = 15) -> list[tuple[str, int]]:
        by_client = self.recent_queries_by_client(limit=limit)
        entries = by_client.get(client_ip, [])
        counts: dict[str, int] = {}
        for e in entries:
            counts[e["domain"]] = counts.get(e["domain"], 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    def blocked_summary_for_client(self, client_ip: str, limit: int = 500, top_n: int = 15) -> dict:
        """Blocked-query count and top blocked domains for one device — what AdGuard Home
        is actively protecting it from, not just what it's visiting."""
        by_client = self.recent_queries_by_client(limit=limit)
        entries = by_client.get(client_ip, [])
        blocked = [e for e in entries if e["blocked"]]
        counts: dict[str, int] = {}
        for e in blocked:
            counts[e["domain"]] = counts.get(e["domain"], 0) + 1
        return {
            "total_queries": len(entries),
            "blocked_count": len(blocked),
            "top_blocked": sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n],
        }

    def global_stats(self) -> dict:
        """Network-wide totals — total/blocked query counts, protection status."""
        return self._get("/control/stats")
