"""
IP enrichment: AbuseIPDB reputation scores + GeoIP via ip-api.com.
Results are cached in the DB for 24 hours to avoid hammering external APIs.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from database import IpReputationCache, SessionLocal, get_service_setting

logger = logging.getLogger("enrichment")

_CACHE_TTL_HOURS = 24
_PRIVATE_RANGES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1", "fd", "fe80",
)

ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam", 13: "VPN IP",
    14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_RANGES)


def _is_cache_fresh(row: IpReputationCache) -> bool:
    if not row.fetched_at:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_CACHE_TTL_HOURS)
    fetched = row.fetched_at
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    return fetched > cutoff


async def enrich_ip(ip: str) -> dict:
    """Return cached or freshly-fetched reputation data for an IP."""
    if _is_private(ip):
        return {"ip": ip, "private": True, "abuse_score": 0}

    db = SessionLocal()
    try:
        cached = db.query(IpReputationCache).filter_by(ip=ip).first()
        if cached and _is_cache_fresh(cached):
            result = _row_to_dict(cached)
        else:
            data = await _fetch_enrichment(ip)
            if cached:
                for k, v in data.items():
                    if hasattr(cached, k):
                        setattr(cached, k, v)
                cached.fetched_at = datetime.now(timezone.utc)
            else:
                db.add(IpReputationCache(ip=ip, fetched_at=datetime.now(timezone.utc), **{
                    k: v for k, v in data.items() if k != "ip"
                }))
            db.commit()
            result = {"ip": ip, **data}

        # Threat intel lookup
        try:
            from threat_intel import check_threat_intel
            ti = check_threat_intel(ip, db)
            if ti:
                result["threat_intel"] = ti
        except Exception as ti_exc:
            logger.debug("Threat intel lookup failed for %s: %s", ip, ti_exc)

        return result
    except Exception as exc:
        logger.warning("Enrichment failed for %s: %s", ip, exc)
        return {"ip": ip, "error": str(exc)}
    finally:
        db.close()


async def _fetch_enrichment(ip: str) -> dict:
    result: dict = {}

    # GeoIP via ip-api.com (free, no key, 45 req/min)
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,city,isp,org,as"},
            )
            if r.status_code == 200:
                geo = r.json()
                if geo.get("status") == "success":
                    result["country_code"] = geo.get("countryCode")
                    result["country_name"] = geo.get("country")
                    result["geo_city"] = geo.get("city")
                    result["isp"] = geo.get("isp") or geo.get("org")
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)

    # AbuseIPDB (requires API key stored in service settings)
    abuse_key = get_service_setting("abuseipdb_api_key")
    if abuse_key:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                )
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    result["abuse_score"] = d.get("abuseConfidenceScore", 0)
                    result["abuse_reports"] = d.get("totalReports", 0)
                    result["is_tor"] = d.get("isTor", False)
                    result["is_vpn"] = d.get("isPublic") is False
                    cats = d.get("reports", [])
                    cat_ids = set()
                    for rep in cats:
                        cat_ids.update(rep.get("categories", []))
                    result["threat_categories"] = json.dumps(
                        [ABUSE_CATEGORIES.get(c, str(c)) for c in sorted(cat_ids)]
                    )
        except Exception as exc:
            logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)

    return result


def _row_to_dict(row: IpReputationCache) -> dict:
    cats = []
    if row.threat_categories:
        try:
            cats = json.loads(row.threat_categories)
        except Exception:
            pass
    return {
        "ip": row.ip,
        "abuse_score": row.abuse_score,
        "abuse_reports": row.abuse_reports,
        "country_code": row.country_code,
        "country_name": row.country_name,
        "geo_city": row.geo_city,
        "isp": row.isp,
        "is_tor": row.is_tor,
        "is_vpn": row.is_vpn,
        "threat_categories": cats,
        "cached": True,
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
    }


async def enrich_batch(ips: list[str]) -> dict[str, dict]:
    """Enrich multiple IPs, skipping private addresses. Returns ip -> data map."""
    results = {}
    for ip in set(ips):
        if ip and not _is_private(ip):
            results[ip] = await enrich_ip(ip)
    return results
