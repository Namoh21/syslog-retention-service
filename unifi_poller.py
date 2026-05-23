"""
UniFi Network Application API poller.

Periodically fetches DPI (Deep Packet Inspection) data from a local UDM Pro
controller and stores per-client application/category records in the database.

Authentication:
  - API key (preferred): Settings → System → Control Plane → API in UniFi UI
    Header: X-API-KEY (UniFi OS 3.x+) — NOT Authorization: Bearer
  - Username/password: cookie + X-CSRF-Token session (fallback)

Settings (stored in service_settings DB table):
  unifi_enabled       true/false
  unifi_url           https://10.10.100.1  (UDM Pro local address)
  unifi_api_key       API key from UniFi UI
  unifi_username      fallback username
  unifi_password      fallback password (stored encrypted)
  unifi_site          default
  unifi_poll_interval seconds between polls (default 300)
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("unifi_poller")

_stats = {
    "last_poll":     None,
    "last_status":   "not started",
    "records_stored": 0,
    "errors":        0,
    "clients_seen":  0,
}


# ── UniFi API client ──────────────────────────────────────────────────────────

class UniFiClient:
    """
    Async client for the UniFi Network Application REST API.

    Auth priority:
      1. API key  → X-API-KEY header (UDM OS 3.x / Network App 8+)
      2. Username/password → cookie session + X-CSRF-Token
    """

    def __init__(self, base_url: str, api_key: str = "",
                 username: str = "", password: str = "", site: str = "default"):
        self.base_url = base_url.rstrip("/")
        self.api_key  = (api_key or "").strip()
        self.username = username
        self.password = password
        self.site     = site or "default"
        self._session_cookies: dict = {}
        self._csrf_token: str = ""

    # ── Low-level request ─────────────────────────────────────────────────────

    async def _request(self, method: str, path: str, json=None) -> dict:
        import httpx

        # Build auth headers — prefer API key
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            # UniFi OS 3.x uses X-API-KEY, not Authorization: Bearer
            headers["X-API-KEY"] = self.api_key
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token

        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(
            verify=False, timeout=30.0, cookies=self._session_cookies,
            follow_redirects=True,
        ) as client:
            r = await client.request(method, url, headers=headers, json=json)

            # 401 with API key → wrong key or wrong header name, surface clearly
            if r.status_code == 401 and self.api_key:
                raise RuntimeError(
                    f"API key authentication failed (401). "
                    f"Verify the key in UniFi → Settings → System → Control Plane → API. "
                    f"URL tried: {url}"
                )

            # 401 without API key → attempt session login
            if r.status_code == 401 and not self.api_key:
                await self._login(client)
                headers["X-CSRF-Token"] = self._csrf_token
                r = await client.request(method, url, headers=headers, json=json,
                                         cookies=self._session_cookies)

            r.raise_for_status()
            return r.json()

    async def _login(self, client) -> None:
        """Obtain a session cookie + CSRF token via username/password."""
        import httpx
        payload = {"username": self.username, "password": self.password,
                   "remember": False, "strict": True}

        # UDM Pro (UniFi OS): /api/auth/login
        # Legacy controller:  /api/login
        for path in ["/api/auth/login", "/api/login"]:
            try:
                r = await client.post(
                    f"{self.base_url}{path}", json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code in (200, 201):
                    self._session_cookies = dict(r.cookies)
                    # UniFi OS returns CSRF token in X-CSRF-Token header
                    self._csrf_token = r.headers.get("X-CSRF-Token", "")
                    logger.info("UniFi session login OK via %s (CSRF=%s)",
                                path, bool(self._csrf_token))
                    return
                logger.debug("Login attempt %s → HTTP %d", path, r.status_code)
            except Exception as exc:
                logger.debug("Login attempt %s failed: %s", path, exc)

        raise RuntimeError(
            "UniFi login failed — check username/password. "
            "If 2FA is enabled, use an API key instead."
        )

    # ── API helpers ───────────────────────────────────────────────────────────

    async def get_system_info(self) -> dict:
        """Controller version info — used to verify connectivity."""
        for path in [
            "/proxy/network/api/s/default/stat/sysinfo",
            "/api/s/default/stat/sysinfo",
        ]:
            try:
                data = await self._request("GET", path)
                rows = data.get("data", [{}])
                return rows[0] if rows else {}
            except Exception as exc:
                last_exc = exc
                logger.debug("sysinfo %s failed: %s", path, exc)
        raise last_exc  # type: ignore[possibly-unbound]

    async def get_sites(self) -> list[dict]:
        """List all sites: [{"name": "default", "desc": "Home"}, ...]"""
        for path in ["/proxy/network/api/self/sites", "/api/self/sites"]:
            try:
                data = await self._request("GET", path)
                return [
                    {"name": s.get("name", ""), "desc": s.get("desc", s.get("name", ""))}
                    for s in data.get("data", [])
                    if s.get("name")
                ]
            except Exception as exc:
                logger.debug("sites %s failed: %s", path, exc)
        return []

    async def get_config_snapshot(self, site: str = "") -> dict:
        """
        Fetch key configuration items from the controller.
        Returns a dict with firewall_rules, port_forwards, networks,
        ips_settings, devices_summary, traffic_rules, firewall_groups.
        Skips any section that fails rather than aborting entirely.
        """
        s = site or self.site

        async def _safe(path: str) -> list:
            for p in [f"/proxy/network/api/s/{s}/{path}",
                      f"/api/s/{s}/{path}"]:
                try:
                    d = await self._request("GET", p)
                    return d.get("data", [])
                except Exception:
                    pass
            return []

        async def _safe_setting(subsystem: str) -> dict:
            for p in [f"/proxy/network/api/s/{s}/get/setting/{subsystem}",
                      f"/api/s/{s}/get/setting/{subsystem}"]:
                try:
                    d = await self._request("GET", p)
                    rows = d.get("data", [])
                    return rows[0] if rows else {}
                except Exception:
                    pass
            return {}

        import asyncio as _aio
        (fw_rules, fw_groups, port_fwd, networks,
         wlans, traffic_rules, devices, routing) = await _aio.gather(
            _safe("rest/firewallrule"),
            _safe("rest/firewallgroup"),
            _safe("rest/portforward"),
            _safe("rest/networkconf"),
            _safe("rest/wlanconf"),
            _safe("rest/trafficrule"),
            _safe("stat/device"),
            _safe("rest/routing"),
            return_exceptions=False,
        )
        ips = await _safe_setting("ips")

        # Summarise devices (keep small)
        devices_summary = [
            {k: d.get(k) for k in ("name", "model", "type", "ip", "version",
                                    "uptime", "state") if d.get(k)}
            for d in devices[:20]
        ]

        return {
            "firewall_rules":  fw_rules,
            "firewall_groups": fw_groups,
            "port_forwards":   port_fwd,
            "networks":        networks,
            "wifi_networks":   wlans,
            "traffic_rules":   traffic_rules,
            "devices":         devices_summary,
            "static_routes":   routing,
            "ips_settings":    ips,
        }

    async def get_dpi_stats(self) -> list[dict]:
        """Per-client DPI breakdown: app name, category, traffic bytes."""
        for path in [
            f"/proxy/network/api/s/{self.site}/stat/dpi",
            f"/api/s/{self.site}/stat/dpi",
        ]:
            try:
                data = await self._request("GET", path)
                return data.get("data", [])
            except Exception as exc:
                logger.debug("dpi %s failed: %s", path, exc)
        return []

    async def get_clients(self) -> list[dict]:
        """Active client list — provides hostname + IP per MAC."""
        for path in [
            f"/proxy/network/api/s/{self.site}/stat/sta",
            f"/api/s/{self.site}/stat/sta",
        ]:
            try:
                data = await self._request("GET", path)
                return data.get("data", [])
            except Exception as exc:
                logger.debug("clients %s failed: %s", path, exc)
        return []


# ── DPI record storage ────────────────────────────────────────────────────────

def _store_dpi_records(records: list[dict], clients_by_mac: dict) -> int:
    from database import DpiRecord, SessionLocal
    if not records:
        logger.info("DPI: API returned 0 records — check that Deep Packet Inspection "
                    "is enabled in UniFi → Settings → Traffic Management → DPI")
        return 0

    # Log a sample so we can see the actual field names in the response
    if records:
        logger.info("DPI sample record keys: %s", list(records[0].keys()))
        logger.info("DPI sample record: %s", {k: v for k, v in records[0].items()
                                               if k in ("mac","cat","cat_name","app",
                                                        "app_proto","tx_bytes","rx_bytes",
                                                        "type","name")})

    db = SessionLocal()
    count = 0
    now = datetime.now(timezone.utc)
    try:
        for r in records:
            mac = r.get("mac", "")
            # Try all known field name variants across firmware versions
            cat = (r.get("cat_name") or r.get("cat") or
                   r.get("category") or r.get("category_name") or "")
            app = (r.get("app_proto") or r.get("app") or
                   r.get("application") or r.get("name") or r.get("type") or "")
            tx  = int(r.get("tx_bytes", 0) or 0)
            rx  = int(r.get("rx_bytes", 0) or 0)

            # Store even if bytes are 0 as long as we have a category or app name
            if not (cat or app):
                continue

            client   = clients_by_mac.get(mac, {})
            src_ip   = client.get("ip") or r.get("ip") or None
            hostname = client.get("hostname") or client.get("name") or None
            db.add(DpiRecord(
                polled_at=now,
                mac_address=mac or None,
                src_ip=src_ip,
                hostname=hostname,
                app_name=str(app)[:128] if app else None,
                url_category=str(cat)[:128] if cat else None,
                tx_bytes=tx,
                rx_bytes=rx,
            ))
            count += 1
        db.commit()
        logger.info("DPI: stored %d / %d records", count, len(records))
    except Exception as exc:
        logger.error("DPI store error: %s", exc)
        db.rollback()
    finally:
        db.close()
    return count


# ── Credential resolution ─────────────────────────────────────────────────────

def _load_credentials() -> tuple[str, str, str, str, str]:
    """Returns (url, api_key, username, password, site) from DB settings."""
    from database import get_service_setting, decrypt_value
    url      = get_service_setting("unifi_url") or ""
    api_key  = get_service_setting("unifi_api_key") or ""
    username = get_service_setting("unifi_username") or ""
    enc_pass = get_service_setting("unifi_password") or ""
    password = decrypt_value(enc_pass) if enc_pass else ""
    site     = get_service_setting("unifi_site") or "default"
    return url, api_key, username, password, site


# ── Poll loop ─────────────────────────────────────────────────────────────────

async def _poll_once(url="", api_key="", username="", password="",
                     site="default") -> int:
    """Execute one poll cycle. If credentials are empty, loads from DB."""
    if not url:
        url, api_key, username, password, site = _load_credentials()
    if not url:
        raise ValueError("unifi_url not configured")
    if not api_key and not (username and password):
        raise ValueError("Configure an API key or username+password in Service Settings → UniFi")

    client = UniFiClient(url, api_key=api_key, username=username,
                         password=password, site=site)
    clients = await client.get_clients()
    clients_by_mac = {c.get("mac", ""): c for c in clients if c.get("mac")}
    _stats["clients_seen"] = len(clients_by_mac)

    dpi = await client.get_dpi_stats()
    stored = await asyncio.to_thread(_store_dpi_records, dpi, clients_by_mac)
    return stored


async def run_unifi_poller():
    """Background task — polls on configured interval when enabled."""
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
            _stats.update(last_poll=datetime.now(timezone.utc).isoformat(),
                          last_status=f"OK — {stored} DPI records stored",
                          errors=0)
            _stats["records_stored"] += stored
            logger.info("UniFi poll: %d DPI records, %d clients",
                        stored, _stats["clients_seen"])
        except Exception as exc:
            _stats["errors"] += 1
            _stats.update(last_status=f"Error: {exc}",
                          last_poll=datetime.now(timezone.utc).isoformat())
            logger.warning("UniFi poll failed: %s", exc)


# ── On-demand operations ──────────────────────────────────────────────────────

async def fetch_config_snapshot() -> dict:
    """Fetch UniFi config for injection into AI analysis context."""
    url, api_key, username, password, site = _load_credentials()
    if not url:
        return {}
    try:
        client = UniFiClient(url, api_key=api_key, username=username,
                             password=password, site=site)
        return await client.get_config_snapshot(site)
    except Exception as exc:
        logger.warning("Config snapshot failed: %s", exc)
        return {}


def get_stats() -> dict:
    return dict(_stats)


async def poll_now() -> dict:
    try:
        stored = await _poll_once()
        _stats.update(last_poll=datetime.now(timezone.utc).isoformat(),
                      last_status=f"OK — {stored} DPI records stored", errors=0)
        _stats["records_stored"] += stored
        return {"ok": True, "stored": stored, "clients": _stats["clients_seen"]}
    except Exception as exc:
        _stats["errors"] += 1
        _stats.update(last_status=f"Error: {exc}",
                      last_poll=datetime.now(timezone.utc).isoformat())
        return {"ok": False, "error": str(exc)}


async def test_connection(url: str = "", api_key: str = "",
                          username: str = "", password: str = "",
                          site: str = "default") -> dict:
    """
    Test connectivity. Always loads DB settings as the base, then overlays
    any non-empty values passed directly from the UI form. This means:
    - User can test before saving (new values override DB)
    - Placeholder bullets in the UI (empty api_key sent) → DB key used
    """
    db_url, db_key, db_user, db_pass, db_site = _load_credentials()
    # Overlay: form value wins if non-empty, otherwise use DB value
    url      = url.strip()      or db_url
    api_key  = api_key.strip()  or db_key
    username = username.strip() or db_user
    password = password         or db_pass
    site     = site.strip()     or db_site

    if not url:
        return {"ok": False, "error": "Controller URL not configured — save settings first"}
    if not api_key and not (username and password):
        return {"ok": False,
                "error": "No credentials found — enter an API key or username/password and save (or enter them in the form before testing)"}

    try:
        client  = UniFiClient(url, api_key=api_key, username=username,
                              password=password, site=site)
        info    = await client.get_system_info()
        version = (info.get("version") or info.get("sw_ver") or
                   info.get("ubnt_device_type") or "unknown")
        sites   = await client.get_sites()
        return {
            "ok":       True,
            "version":  version,
            "hostname": info.get("hostname", ""),
            "site":     site,
            "sites":    sites,   # [{"name": "default", "desc": "Home"}, ...]
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
