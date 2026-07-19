"""
dashboard/main.py — Network Companion's web dashboard backend.

Run with:  python -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8642
(from the project root, so the `database`/`config`/`netutils` imports resolve)
"""

import asyncio
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import config
import database
from adguard_client import AdGuardClient
from netutils import get_default_gateway

app = FastAPI(title="Network Companion")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_cfg = config.load()
_agh = AdGuardClient(_cfg["adguard_url"], _cfg["adguard_username"], _cfg["adguard_password"]) \
    if _cfg.get("adguard_username") else None

STATIC_DIR = Path(__file__).parent / "static"
SCAN_STALE_AFTER_SECONDS = 150


# ---------- Auth helpers ----------

def _load_jose():
    try:
        from jose import JWTError, jwt as jose_jwt
        return jose_jwt, JWTError
    except ImportError:
        return None, None


def _load_bcrypt():
    try:
        import bcrypt
        return bcrypt
    except ImportError:
        return None


def _get_secret() -> str:
    cfg = config.load()
    secret = cfg.get("auth_secret_key", "")
    if not secret:
        # auto-generate and persist a secret so restarts don't invalidate existing tokens
        secret = secrets.token_hex(32)
        cfg["auth_secret_key"] = secret
        config.save(cfg)
    return secret


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def _create_token(username: str, role: str) -> str:
    jose_jwt, _ = _load_jose()
    if jose_jwt is None:
        return ""
    cfg = config.load()
    expire_hours = cfg.get("auth_token_expire_hours", 24)
    payload = {
        "sub": username,
        "role": role,
        "exp": int(time.time()) + expire_hours * 3600,
    }
    return jose_jwt.encode(payload, _get_secret(), algorithm="HS256")


def _decode_token(token: str) -> dict | None:
    jose_jwt, JWTError = _load_jose()
    if jose_jwt is None:
        return None
    try:
        return jose_jwt.decode(token, _get_secret(), algorithms=["HS256"])
    except Exception:
        return None


def _current_user(token: str = Depends(oauth2_scheme)) -> dict | None:
    cfg = config.load()
    if not cfg.get("auth_enabled"):
        return {"username": "admin", "role": "admin"}
    if not token:
        return None
    return _decode_token(token)


def _require_admin(user: dict | None = Depends(_current_user)):
    if user is None or user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def _require_viewer(user: dict | None = Depends(_current_user)):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


def _ensure_initial_admin():
    """Bootstrap first admin if auth is enabled and no users exist yet."""
    cfg = config.load()
    if not cfg.get("auth_enabled"):
        return
    if database.count_admins() > 0:
        return
    password = cfg.get("auth_initial_admin_password", "")
    if not password:
        password = "admin"
        print("[!] Auth enabled but auth_initial_admin_password not set in config.json.")
        print("[!] Default admin password is 'admin' — CHANGE IT immediately via the dashboard.")
    bcrypt = _load_bcrypt()
    if bcrypt is None:
        print("[!] bcrypt not installed — cannot create initial admin. Run: pip install bcrypt")
        return
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    database.create_user("admin", pw_hash, "admin")
    print("[i] Created initial admin user. Change the password in the dashboard.")


# ---------- Pydantic models ----------

class RenameRequest(BaseModel):
    friendly_name: str

class TagsRequest(BaseModel):
    tags: Optional[str] = None

class QuotaRequest(BaseModel):
    quota_mb: Optional[int] = None

class ArmRequest(BaseModel):
    router_ip: Optional[str] = None

class QuotaActionRequest(BaseModel):
    action: str
    throttle_rate_kbps: Optional[int] = None

class ScheduleRuleRequest(BaseModel):
    label: Optional[str] = None
    days_of_week: str
    start_minute: int
    end_minute: int
    action: str = "block"
    throttle_rate_kbps: Optional[int] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"

class ChangePasswordRequest(BaseModel):
    username: str
    new_password: str


# ---------- Startup ----------

@app.on_event("startup")
def startup():
    database.init_db()
    _ensure_initial_admin()


# ---------- Auth endpoints ----------

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    cfg = config.load()
    if not cfg.get("auth_enabled"):
        return {"access_token": "", "token_type": "bearer", "role": "admin"}

    bcrypt = _load_bcrypt()
    if bcrypt is None:
        raise HTTPException(500, "bcrypt not installed on server")

    user = database.get_user_by_username(form.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(form.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = _create_token(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.get("/api/auth/me")
def auth_me(user: dict = Depends(_require_viewer)):
    return {"username": user["username"], "role": user["role"]}


@app.get("/api/auth/users")
def list_users(user: dict = Depends(_require_admin)):
    return {"users": database.get_all_users()}


@app.post("/api/auth/users")
def create_user(body: CreateUserRequest, user: dict = Depends(_require_admin)):
    bcrypt = _load_bcrypt()
    if bcrypt is None:
        raise HTTPException(500, "bcrypt not installed")
    if body.role not in ("admin", "viewer"):
        raise HTTPException(400, "role must be 'admin' or 'viewer'")
    if database.get_user_by_username(body.username):
        raise HTTPException(409, "Username already exists")
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    uid = database.create_user(body.username, pw_hash, body.role)
    return {"ok": True, "id": uid}


@app.post("/api/auth/users/password")
def change_password(body: ChangePasswordRequest, user: dict = Depends(_require_admin)):
    bcrypt = _load_bcrypt()
    if bcrypt is None:
        raise HTTPException(500, "bcrypt not installed")
    if not database.get_user_by_username(body.username):
        raise HTTPException(404, "User not found")
    pw_hash = bcrypt.hashpw(body.new_password.encode(), bcrypt.gensalt()).decode()
    database.update_user_password(body.username, pw_hash)
    return {"ok": True}


@app.delete("/api/auth/users/{username}")
def delete_user(username: str, user: dict = Depends(_require_admin)):
    if username == user["username"]:
        raise HTTPException(400, "Cannot delete your own account")
    if not database.get_user_by_username(username):
        raise HTTPException(404, "User not found")
    # Prevent deleting the last admin
    target = database.get_user_by_username(username)
    if target and target["role"] == "admin" and database.count_admins() <= 1:
        raise HTTPException(400, "Cannot delete the last admin account")
    database.delete_user(username)
    return {"ok": True}


# ---------- Devices (read — viewer) ----------

@app.get("/api/devices")
def list_devices(user: dict = Depends(_require_viewer)):
    devices = database.get_all_devices()
    month_start = database.get_month_start_ts()
    for d in devices:
        sent, received = database.get_usage_since(d["mac"], month_start)
        d["usage_month_bytes_sent"] = sent
        d["usage_month_bytes_received"] = received
        d["usage_month_total_mb"] = round((sent + received) / (1024 * 1024), 2)
        d["effective_policy"] = database.get_effective_policy(d["mac"]) if d["bandwidth_armed"] else None
    return {"devices": devices}


@app.get("/api/devices/{mac}/sites")
def device_sites(mac: str, limit: int = 500, top_n: int = 15, user: dict = Depends(_require_viewer)):
    if _agh is None:
        raise HTTPException(503, "AdGuard Home isn't configured")
    devices = {d["mac"]: d for d in database.get_all_devices()}
    device = devices.get(mac)
    if not device or not device["ip"]:
        raise HTTPException(404, "Unknown device or no IP on record yet")
    try:
        top = _agh.top_domains_for_client(device["ip"], limit=limit, top_n=top_n)
    except Exception as e:
        raise HTTPException(502, f"Couldn't reach AdGuard Home: {e}")
    return {"ip": device["ip"], "top_domains": [{"domain": d, "count": c} for d, c in top]}


@app.get("/api/devices/{mac}/blocked")
def device_blocked(mac: str, limit: int = 500, top_n: int = 15, user: dict = Depends(_require_viewer)):
    if _agh is None:
        raise HTTPException(503, "AdGuard Home isn't configured")
    devices = {d["mac"]: d for d in database.get_all_devices()}
    device = devices.get(mac)
    if not device or not device["ip"]:
        raise HTTPException(404, "Unknown device or no IP on record yet")
    try:
        summary = _agh.blocked_summary_for_client(device["ip"], limit=limit, top_n=top_n)
    except Exception as e:
        raise HTTPException(502, f"Couldn't reach AdGuard Home: {e}")
    return {
        "ip": device["ip"],
        "total_queries": summary["total_queries"],
        "blocked_count": summary["blocked_count"],
        "top_blocked": [{"domain": d, "count": c} for d, c in summary["top_blocked"]],
    }


@app.get("/api/devices/{mac}/bandwidth_history")
def bandwidth_history(mac: str, minutes: int = 30, user: dict = Depends(_require_viewer)):
    since = time.time() - minutes * 60
    with database.get_conn() as conn:
        rows = conn.execute(
            "SELECT at, bytes_sent, bytes_received FROM bandwidth_samples WHERE mac = ? AND at >= ? ORDER BY at ASC",
            (mac, since),
        ).fetchall()
    return {"samples": [dict(r) for r in rows]}


@app.get("/api/devices/{mac}/bandwidth_trend")
def bandwidth_trend(mac: str, days: int = 14, user: dict = Depends(_require_viewer)):
    since = time.time() - days * 86400
    hourly = database.get_hourly_history(mac, since)
    daily: dict[float, dict] = {}
    for h in hourly:
        day_bucket = h["hour_start"] - (h["hour_start"] % 86400)
        d = daily.setdefault(day_bucket, {"day_start": day_bucket, "bytes_sent": 0, "bytes_received": 0})
        d["bytes_sent"] += h["bytes_sent"]
        d["bytes_received"] += h["bytes_received"]
    return {"days": sorted(daily.values(), key=lambda x: x["day_start"])}


@app.get("/api/devices/{mac}/policy")
def get_policy(mac: str, user: dict = Depends(_require_viewer)):
    return database.get_effective_policy(mac)


@app.get("/api/devices/{mac}/schedule_rules")
def get_schedule_rules(mac: str, user: dict = Depends(_require_viewer)):
    return {"rules": database.list_schedule_rules(mac)}


# ---------- Devices (write — admin only) ----------

@app.post("/api/devices/{mac}/name")
def rename_device(mac: str, body: RenameRequest, user: dict = Depends(_require_admin)):
    database.set_device_name(mac, body.friendly_name)
    return {"ok": True}


@app.post("/api/devices/{mac}/tags")
def set_tags(mac: str, body: TagsRequest, user: dict = Depends(_require_admin)):
    database.set_device_tags(mac, body.tags)
    return {"ok": True}


@app.post("/api/devices/{mac}/quota")
def set_quota(mac: str, body: QuotaRequest, user: dict = Depends(_require_admin)):
    database.set_device_quota(mac, body.quota_mb)
    return {"ok": True}


@app.post("/api/devices/{mac}/arm")
def arm_device(mac: str, body: ArmRequest, user: dict = Depends(_require_admin)):
    router_ip = body.router_ip or _cfg.get("router_ip") or get_default_gateway()
    if not router_ip:
        raise HTTPException(400, "Could not determine router IP")
    database.arm_bandwidth_capture(mac, router_ip)
    return {"ok": True, "router_ip": router_ip}


@app.post("/api/devices/{mac}/disarm")
def disarm_device(mac: str, user: dict = Depends(_require_admin)):
    database.disarm_bandwidth_capture(mac, detail="disarmed via dashboard")
    return {"ok": True}


@app.post("/api/devices/{mac}/quota_action")
def set_quota_action(mac: str, body: QuotaActionRequest, user: dict = Depends(_require_admin)):
    if body.action == "throttle" and not body.throttle_rate_kbps:
        raise HTTPException(400, "throttle_rate_kbps is required when action is 'throttle'")
    database.set_quota_action(mac, body.action, body.throttle_rate_kbps)
    return {"ok": True}


@app.post("/api/devices/{mac}/schedule_rules")
def create_schedule_rule(mac: str, body: ScheduleRuleRequest, user: dict = Depends(_require_admin)):
    if body.action == "throttle" and not body.throttle_rate_kbps:
        raise HTTPException(400, "throttle_rate_kbps is required when action is 'throttle'")
    if not (0 <= body.start_minute < 1440) or not (0 <= body.end_minute <= 1440):
        raise HTTPException(400, "start_minute/end_minute must be within a single day (0-1439)")
    rule_id = database.add_schedule_rule(
        mac, body.label, body.days_of_week, body.start_minute, body.end_minute,
        body.action, body.throttle_rate_kbps,
    )
    return {"ok": True, "rule_id": rule_id}


@app.delete("/api/devices/{mac}/schedule_rules/{rule_id}")
def delete_schedule_rule(mac: str, rule_id: int, user: dict = Depends(_require_admin)):
    database.remove_schedule_rule(rule_id)
    return {"ok": True}


@app.post("/api/devices/{mac}/schedule_rules/{rule_id}/toggle")
def toggle_schedule_rule(mac: str, rule_id: int, enabled: bool, user: dict = Depends(_require_admin)):
    database.set_schedule_rule_enabled(rule_id, enabled)
    return {"ok": True}


@app.post("/api/emergency_unblock")
def emergency_unblock(user: dict = Depends(_require_admin)):
    count = database.disarm_all_devices()
    return {"ok": True, "devices_disarmed": count}


# ---------- AdGuard / DNS ----------

@app.get("/api/adguard/stats")
def adguard_global_stats(user: dict = Depends(_require_viewer)):
    if _agh is None:
        raise HTTPException(503, "AdGuard Home isn't configured")
    try:
        return _agh.global_stats()
    except Exception as e:
        raise HTTPException(502, f"Couldn't reach AdGuard Home: {e}")


@app.get("/api/dns/recent")
def dns_recent(limit: int = 100, user: dict = Depends(_require_viewer)):
    """Latest DNS queries across all clients — for the real-time query panel."""
    if _agh is None:
        raise HTTPException(503, "AdGuard Home isn't configured")
    try:
        by_client = _agh.recent_queries_by_client(limit=limit)
    except Exception as e:
        raise HTTPException(502, f"Couldn't reach AdGuard Home: {e}")

    # Flatten and sort by time descending, attach device name
    devices = {d["ip"]: d for d in database.get_all_devices() if d.get("ip")}
    entries = []
    for ip, queries in by_client.items():
        dev = devices.get(ip, {})
        name = dev.get("friendly_name") or dev.get("hostname") or ip
        for q in queries:
            entries.append({
                "client_ip": ip,
                "device_name": name,
                "domain": q["domain"],
                "time": q.get("time"),
                "blocked": q.get("blocked", False),
            })
    entries.sort(key=lambda e: e.get("time") or "", reverse=True)
    return {"queries": entries[:limit]}


@app.get("/api/dns/stream")
async def dns_stream(request: Request, token: Optional[str] = None, user: dict = Depends(_current_user)):
    """Server-Sent Events stream of live DNS queries, polled from AdGuard every 3 seconds.
    Accepts auth token as ?token= query param because browser EventSource doesn't support headers."""
    # If auth is enabled and no user from header, try query param token
    cfg = config.load()
    if cfg.get("auth_enabled") and user is None and token:
        user = _decode_token(token)
    if cfg.get("auth_enabled") and user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if _agh is None:
        raise HTTPException(503, "AdGuard Home isn't configured")

    async def event_generator():
        seen_keys: set = set()
        while True:
            if await request.is_disconnected():
                break
            try:
                by_client = _agh.recent_queries_by_client(limit=200)
                devices = {d["ip"]: d for d in database.get_all_devices() if d.get("ip")}
                new_entries = []
                for ip, queries in by_client.items():
                    dev = devices.get(ip, {})
                    name = dev.get("friendly_name") or dev.get("hostname") or ip
                    for q in queries:
                        key = (ip, q["domain"], q.get("time"))
                        if key not in seen_keys:
                            seen_keys.add(key)
                            new_entries.append({
                                "client_ip": ip,
                                "device_name": name,
                                "domain": q["domain"],
                                "time": q.get("time"),
                                "blocked": q.get("blocked", False),
                            })
                # Prune seen_keys to avoid unbounded growth
                if len(seen_keys) > 2000:
                    seen_keys.clear()
                for entry in new_entries:
                    yield f"data: {json.dumps(entry)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/dns/privacy_score/{mac}")
def dns_privacy_score(mac: str, user: dict = Depends(_require_viewer)):
    """Compute a simple privacy score (0-100, higher = more private) for a device.

    Scoring: starts at 100, deducts points for queries to known telemetry/tracking domains.
    A rough heuristic — the real value is seeing *which* domains are triggering deductions.
    """
    if _agh is None:
        raise HTTPException(503, "AdGuard Home isn't configured")
    TELEMETRY_KEYWORDS = [
        "telemetry", "analytics", "tracking", "metrics", "stats.", "collector",
        "appstats", "crashlytics", "amplitude", "mixpanel", "segment.io",
        "hotjar", "heap.io", "fullstory", "mouseflow", "clarity.ms",
        "doubleclick", "googlesyndication", "googletag", "google-analytics",
        "facebook.com/tr", "connect.facebook.net", "ads.twitter", "ads.linkedin",
    ]
    devices = {d["mac"]: d for d in database.get_all_devices()}
    device = devices.get(mac)
    if not device or not device["ip"]:
        raise HTTPException(404, "Unknown device or no IP")
    try:
        top = _agh.top_domains_for_client(device["ip"], limit=500, top_n=100)
    except Exception as e:
        raise HTTPException(502, str(e))

    telemetry_hits = []
    total_queries = sum(c for _, c in top)
    telemetry_queries = 0
    for domain, count in top:
        if any(kw in domain.lower() for kw in TELEMETRY_KEYWORDS):
            telemetry_hits.append({"domain": domain, "count": count})
            telemetry_queries += count

    score = max(0, 100 - int((telemetry_queries / max(total_queries, 1)) * 100 * 3))
    score = min(100, score)
    return {
        "mac": mac,
        "score": score,
        "total_queries": total_queries,
        "telemetry_queries": telemetry_queries,
        "telemetry_domains": sorted(telemetry_hits, key=lambda x: x["count"], reverse=True)[:10],
    }


# ---------- Speed test ----------

_speedtest_running = False


@app.get("/api/speedtest/history")
def speedtest_history(limit: int = 50, user: dict = Depends(_require_viewer)):
    return {"results": database.get_speedtest_history(limit)}


@app.get("/api/speedtest/latest")
def speedtest_latest(user: dict = Depends(_require_viewer)):
    result = database.get_latest_speedtest()
    return result or {}


@app.post("/api/speedtest/run")
async def run_speedtest_endpoint(user: dict = Depends(_require_admin)):
    """Kick off a speed test in the background. Poll /api/speedtest/latest for the result."""
    global _speedtest_running
    if _speedtest_running:
        raise HTTPException(409, "A speed test is already running")

    async def _run():
        global _speedtest_running
        _speedtest_running = True
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            import speedtest_runner
            await asyncio.get_event_loop().run_in_executor(None, speedtest_runner.run_speedtest)
        except Exception as e:
            print(f"[!] Background speed test failed: {e}")
        finally:
            _speedtest_running = False

    asyncio.create_task(_run())
    return {"ok": True, "message": "Speed test started — poll /api/speedtest/latest for the result"}


@app.get("/api/speedtest/status")
def speedtest_status(user: dict = Depends(_require_viewer)):
    return {"running": _speedtest_running}


# ---------- Topology ----------

@app.get("/api/topology")
def topology(user: dict = Depends(_require_viewer)):
    """Return a graph of nodes (devices) and edges (all connect to the router) for D3 rendering."""
    cfg = config.load()
    router_ip = cfg.get("router_ip") or get_default_gateway() or "unknown"
    devices = database.get_all_devices()
    month_start = database.get_month_start_ts()

    nodes = []
    edges = []

    # Router node
    nodes.append({
        "id": "router",
        "type": "router",
        "label": f"Router ({router_ip})",
        "ip": router_ip,
        "is_online": True,
    })

    # This host node
    from netutils import get_local_ip
    try:
        local_ip = get_local_ip()
    except Exception:
        local_ip = None

    for d in devices:
        node_id = d["mac"]
        label = d.get("friendly_name") or d.get("hostname") or d["mac"]
        is_this_host = d.get("ip") == local_ip

        nodes.append({
            "id": node_id,
            "type": "host" if is_this_host else "device",
            "label": label,
            "mac": d["mac"],
            "ip": d.get("ip"),
            "vendor": d.get("vendor"),
            "is_online": bool(d.get("is_online")),
            "bandwidth_armed": bool(d.get("bandwidth_armed")),
            "tags": d.get("tags") or "",
        })
        edges.append({"source": "router", "target": node_id})

    return {"nodes": nodes, "edges": edges}


# ---------- Events / status ----------

@app.get("/api/events")
def recent_events(limit: int = 50, user: dict = Depends(_require_viewer)):
    return {"events": database.get_recent_events(limit)}


@app.get("/api/status")
def status(user: dict = Depends(_require_viewer)):
    with database.get_conn() as conn:
        last_scan = conn.execute("SELECT * FROM scan_log ORDER BY started_at DESC LIMIT 1").fetchone()
        last_snmp = conn.execute("SELECT at FROM router_bandwidth_samples ORDER BY at DESC LIMIT 1").fetchone()

    scanner_alive = bool(last_scan) and (time.time() - last_scan["finished_at"] < SCAN_STALE_AFTER_SECONDS)
    snmp_alive = bool(last_snmp) and (time.time() - last_snmp["at"] < 120)

    agh_ok = None
    if _agh is not None:
        try:
            _agh.status()
            agh_ok = True
        except Exception:
            agh_ok = False

    armed = database.get_armed_devices()
    cfg = config.load()
    return {
        "scanner_alive": scanner_alive,
        "snmp_alive": snmp_alive,
        "last_scan_at": last_scan["finished_at"] if last_scan else None,
        "adguard_configured": _agh is not None,
        "adguard_reachable": agh_ok,
        "armed_device_count": len(armed),
        "auth_enabled": cfg.get("auth_enabled", False),
        "speedtest_running": _speedtest_running,
    }


@app.get("/api/router/bandwidth_trend")
def router_bandwidth_trend(days: int = 14, user: dict = Depends(_require_viewer)):
    since = time.time() - days * 86400
    with database.get_conn() as conn:
        hourly = conn.execute(
            "SELECT hour_start, bytes_sent, bytes_received FROM router_bandwidth_hourly WHERE hour_start >= ? ORDER BY hour_start",
            (since,),
        ).fetchall()
        raw = conn.execute(
            "SELECT at, bytes_sent, bytes_received FROM router_bandwidth_samples WHERE at >= ? ORDER BY at",
            (max(since, hourly[-1]["hour_start"] + 3600 if hourly else since),),
        ).fetchall()

    buckets: dict[float, dict] = {r["hour_start"]: dict(r) for r in hourly}
    for r in raw:
        bucket = r["at"] - (r["at"] % 3600)
        b = buckets.setdefault(bucket, {"hour_start": bucket, "bytes_sent": 0, "bytes_received": 0})
        b["bytes_sent"] += r["bytes_sent"]
        b["bytes_received"] += r["bytes_received"]

    daily: dict[float, dict] = {}
    for h in buckets.values():
        day_bucket = h["hour_start"] - (h["hour_start"] % 86400)
        d = daily.setdefault(day_bucket, {"day_start": day_bucket, "bytes_sent": 0, "bytes_received": 0})
        d["bytes_sent"] += h["bytes_sent"]
        d["bytes_received"] += h["bytes_received"]

    return {"days": sorted(daily.values(), key=lambda x: x["day_start"])}


# ---------- Frontend ----------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
