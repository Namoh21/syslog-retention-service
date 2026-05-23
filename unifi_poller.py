"""
UniFi Network Application API poller.

Periodically fetches DPI (Deep Packet Inspection) data from a local UDM Pro
controller and stores per-client application/category records in the database.
This data appears in the log viewer alongside syslog entries — domain, category,
and traffic volume per client.

Authentication:
  - API key (preferred): Settings → System → Control Plane → API in UniFi UI
  - Username/password: falls back to cookie-based session if no key is set

Settings (stored in service_settings DB table):
  unifi_enabled       true/false
  unifi_url           https://192.168.1.1  (UDM Pro local address)
  unifi_api_key       Bearer token from UniFi UI  (preferred)
  unifi_username      fallback username
  unifi_password      fallback password (stored encrypted)
  unifi_site          default
  unifi_poll_interval seconds between polls (default 300)
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("unifi_poller")

_poller_task: Optional[asyncio.Task] = None
_stats = {
    "last_poll": None,
    "last_status": "not started",
    "records_stored": 0,
    "errors": 0,
    "clients_seen": 0,
}


# ── UniFi API client ──────────────────────────────────────────────────────────

class UniFiClient:
    def __init__(self, base_url: str, api_key: str = "", username: str = "",
                 password: str = "", site: str = "default"):
        self.base_url = base_url.rstrip("/")
        self.api_key  = api_key
        self.username = username
        self.password = password
        self.site     = site or "default"
        self._cookies: dict = {}

    async def _get(self, path: str) -> dict:
        import httpx
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        async with httpx.AsyncClient(verify=False, timeout=30.0,
                                     cookies=self._cookies) as client:
            r = await client.get(f"{self.base_url}{path}", headers=headers)
            if r.status_code == 401 and not self.api_key:
                await self._login(client)
                r = await client.get(f"{self.base_url}{path}", headers=headers)
            r.raise_for_status()
            return r.json()

    async def _login(self, client) -> None:
        import httpx
        payload = {"username": self.username, "password": self.password}
        # Try modern UniFi OS endpoint first, fall back to legacy
        for path in ["/api/auth/login", "/api/login"]:
            try:
                r = await client.post(f"{self.base_url}{path}", json=payload,
                                      headers={"Content-Type": "application/json"})
                if r.status_code in (200, 201):
                    self._cookies = dict(r.cookies)
                    logger.info("UniFi login OK via %s", path)
                    return
            except Exception:
                continue
        raise RuntimeError("UniFi login failed — check username/password")

    async def get_dpi_stats(self) -> list[dict]:
        """Returns per-client DPI records: {mac, ip, name, app_proto, cat_name, tx_bytes, rx_bytes}."""
        data = await self._get(f"/proxy/network/api/s/{self.site}/stat/dpi")
        return data.get("data", [])

    async def get_clients(self) -> list[dict]:
        """Active client list with hostname, IP, MAC."""
        data = await self._get(f"/proxy/network/api/s/{self.site}/stat/sta")
        return data.get("data", [])

    async def get_system_info(self) -> dict:
        """Controller info — used to verify connectivity."""
        try:
            data = await self._get("/proxy/network/api/s/default/stat/sysinfo")
            return data.get("data", [{}])[0]
        except Exception:
            data = await self._get("/api/s/default/stat/sysinfo")
            return data.get("data", [{}])[0]


# ── DPI record storage ────────────────────────────────────────────────────────

def _store_dpi_records(records: list[dict], clients_by_mac: dict) -> int:
    """Persist DPI stats as DpiRecord rows. Returns count stored."""
    from database import DpiRecord, SessionLocal
    if not records:
        return 0
    db = SessionLocal()
    count = 0
    now = datetime.now(timezone.utc)
    try:
        for r in records:
            mac      = r.get("mac", "")
            cat      = r.get("cat_name") or r.get("cat") or ""
            app      = r.get("app_proto") or r.get("app") or ""
            tx       = int(r.get("tx_bytes", 0) or 0)
            rx       = int(r.get("rx_bytes", 0) or 0)
            if not (cat or app) or (tx + rx) == 0:
                continue
            client   = clients_by_mac.get(mac, {})
            src_ip   = client.get("ip") or r.get("ip") or None
            hostname = client.get("hostname") or client.get("name") or None

            db.add(DpiRecord(
                polled_at=now,
                mac_address=mac or None,
                src_ip=src_ip,
                hostname=hostname,
                app_name=app[:128] if app else None,
                url_category=cat[:128] if cat else None,
                tx_bytes=tx,
                rx_bytes=rx,
            ))
            count += 1
        db.commit()
    except Exception as exc:
        logger.error("DPI store error: %s", exc)
        db.rollback()
    finally:
        db.close()
    return count


# ── Poll loop ─────────────────────────────────────────────────────────────────

async def _poll_once() -> int:
    from database import get_service_setting, decrypt_value
    url      = get_service_setting("unifi_url") or ""
    api_key  = get_service_setting("unifi_api_key") or ""
    username = get_service_setting("unifi_username") or ""
    enc_pass = get_service_setting("unifi_password") or ""
    password = decrypt_value(enc_pass) if enc_pass else ""
    site     = get_service_setting("unifi_site") or "default"

    if not url:
        raise ValueError("unifi_url not configured")
    if not api_key and not (username and password):
        raise ValueError("unifi_api_key or username+password required")

    client = UniFiClient(url, api_key=api_key, username=username,
                         password=password, site=site)

    clients = await client.get_clients()
    clients_by_mac = {c.get("mac", ""): c for c in clients if c.get("mac")}
    _stats["clients_seen"] = len(clients_by_mac)

    dpi = await client.get_dpi_stats()
    stored = await asyncio.to_thread(_store_dpi_records, dpi, clients_by_mac)
    return stored


async def run_unifi_poller():
    """Background task — polls UniFi controller on configured interval."""
    from database import get_service_setting
    logger.info("UniFi poller started")
    while True:
        try:
            interval = int(get_service_setting("unifi_poll_interval") or 300)
        except (ValueError, TypeError):
            interval = 300

        await asyncio.sleep(interval)

        enabled = get_service_setting("unifi_enabled")
        if not enabled or enabled.lower() != "true":
            continue

        try:
            stored = await _poll_once()
            _stats["last_poll"]      = datetime.now(timezone.utc).isoformat()
            _stats["last_status"]    = f"OK — {stored} DPI records stored"
            _stats["records_stored"] += stored
            _stats["errors"]         = 0
            logger.info("UniFi poll: %d DPI records stored, %d clients seen",
                        stored, _stats["clients_seen"])
        except Exception as exc:
            _stats["errors"]      += 1
            _stats["last_status"]  = f"Error: {exc}"
            _stats["last_poll"]    = datetime.now(timezone.utc).isoformat()
            logger.warning("UniFi poll failed: %s", exc)


def get_stats() -> dict:
    return dict(_stats)


async def poll_now() -> dict:
    """Force an immediate poll regardless of schedule. Returns stats."""
    try:
        stored = await _poll_once()
        _stats["last_poll"]      = datetime.now(timezone.utc).isoformat()
        _stats["last_status"]    = f"OK — {stored} DPI records stored"
        _stats["records_stored"] += stored
        _stats["errors"]         = 0
        return {"ok": True, "stored": stored, "clients": _stats["clients_seen"]}
    except Exception as exc:
        _stats["errors"]      += 1
        _stats["last_status"]  = f"Error: {exc}"
        _stats["last_poll"]    = datetime.now(timezone.utc).isoformat()
        return {"ok": False, "error": str(exc)}


async def test_connection() -> dict:
    """Test UniFi API connectivity without storing data."""
    from database import get_service_setting, decrypt_value
    url      = get_service_setting("unifi_url") or ""
    api_key  = get_service_setting("unifi_api_key") or ""
    username = get_service_setting("unifi_username") or ""
    enc_pass = get_service_setting("unifi_password") or ""
    password = decrypt_value(enc_pass) if enc_pass else ""
    site     = get_service_setting("unifi_site") or "default"

    if not url:
        return {"ok": False, "error": "unifi_url not configured"}

    try:
        client = UniFiClient(url, api_key=api_key, username=username,
                             password=password, site=site)
        info = await client.get_system_info()
        version = info.get("version") or info.get("sw_ver") or "unknown"
        return {"ok": True, "version": version, "site": site}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
