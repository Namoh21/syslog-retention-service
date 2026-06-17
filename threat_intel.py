"""
Threat Intel Enrichment — Phase 2
Polls CISA KEV, OTX, MISP, and TAXII 2.1 feeds for threat indicators,
then matches them against incoming SyslogEntry rows.
"""
import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from database import (
    IocMatch, SessionLocal, SyslogEntry, ThreatIndicator, ThreatIntelFeed,
    decrypt_value, encrypt_value, get_service_setting, set_service_setting,
)

logger = logging.getLogger("threat_intel")

# ── Severity helpers ──────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}


def _higher_sev(a: Optional[str], b: Optional[str]) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


# ── Upsert helper ─────────────────────────────────────────────────────────────

def _upsert_indicator(db, feed_id: int, itype: str, value: str, **kwargs) -> bool:
    """Insert or update a ThreatIndicator. Returns True if new."""
    value = (value or "").strip()
    if not value:
        return False
    existing = (
        db.query(ThreatIndicator)
        .filter_by(feed_id=feed_id, indicator_type=itype, value=value)
        .first()
    )
    now = datetime.now(timezone.utc)
    if existing:
        for k, v in kwargs.items():
            if v is not None and hasattr(existing, k):
                setattr(existing, k, v)
        existing.last_seen = now
        return False
    else:
        ind = ThreatIndicator(
            feed_id=feed_id,
            indicator_type=itype,
            value=value,
            first_seen=now,
            last_seen=now,
            **{k: v for k, v in kwargs.items() if hasattr(ThreatIndicator, k)},
        )
        db.add(ind)
        return True


# ── Feed fetchers ─────────────────────────────────────────────────────────────

async def _fetch_cisa_kev(feed: ThreatIntelFeed, db) -> int:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    try:
        cfg = json.loads(feed.config_json or "{}")
    except Exception:
        cfg = {}
    url = cfg.get("url", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    count = 0
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            cve_id = v.get("cveID", "")
            if not cve_id:
                continue
            ransomware = v.get("knownRansomwareCampaignUse", "")
            severity = "critical" if ransomware and ransomware.lower() == "known" else "high"
            tags = ["cisa-kev"]
            if ransomware and ransomware.lower() == "known":
                tags.append("ransomware")
            is_new = _upsert_indicator(
                db, feed.id, "cve", cve_id,
                severity=severity,
                tags_json=json.dumps(tags),
                source_ref=cve_id,
                confidence=90,
            )
            if is_new:
                count += 1
        db.flush()
        logger.info("CISA KEV: %d new indicators from %d vulnerabilities", count, len(vulns))
        return len(vulns)
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        raise


async def _fetch_otx(feed: ThreatIntelFeed, db) -> int:
    """Fetch OTX subscribed pulses."""
    api_key = decrypt_value(feed.encrypted_api_key or "")
    if not api_key:
        raise ValueError("OTX feed requires an API key")

    try:
        cfg = json.loads(feed.config_json or "{}")
    except Exception:
        cfg = {}
    base_url = cfg.get("url", "https://otx.alienvault.com")

    # Build modified_since filter
    modified_since = ""
    if feed.last_polled_at:
        lp = feed.last_polled_at
        if lp.tzinfo is None:
            lp = lp.replace(tzinfo=timezone.utc)
        modified_since = lp.strftime("%Y-%m-%dT%H:%M:%S")

    _OTX_TYPE_MAP = {
        "IPv4": "ip", "IPv6": "ip",
        "domain": "domain", "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash", "FileHash-SHA256": "hash", "FileHash-SHA1": "hash",
        "CVE": "cve",
    }

    total = 0
    page_url = f"{base_url}/api/v1/pulses/subscribed?limit=50"
    if modified_since:
        page_url += f"&modified_since={modified_since}"

    async with httpx.AsyncClient(timeout=30, headers={"X-OTX-API-KEY": api_key}) as client:
        while page_url:
            r = await client.get(page_url)
            r.raise_for_status()
            payload = r.json()
            for pulse in payload.get("results", []):
                adversary = pulse.get("adversary", "")
                severity = "high" if adversary else "medium"
                tags = pulse.get("tags", [])[:10]
                pulse_id = pulse.get("id", "")
                for ind in pulse.get("indicators", []):
                    itype_raw = ind.get("type", "")
                    itype = _OTX_TYPE_MAP.get(itype_raw)
                    if not itype:
                        continue
                    val = ind.get("indicator", "")
                    if not val:
                        continue
                    is_new = _upsert_indicator(
                        db, feed.id, itype, val,
                        severity=severity,
                        tags_json=json.dumps(tags),
                        source_ref=pulse_id,
                        confidence=70,
                    )
                    if is_new:
                        total += 1
            next_url = payload.get("next")
            page_url = next_url if next_url else None

    db.flush()
    logger.info("OTX: %d new indicators", total)
    return total


async def _fetch_misp(feed: ThreatIntelFeed, db) -> int:
    """Fetch MISP attributes via REST search."""
    api_key = decrypt_value(feed.encrypted_api_key or "")
    try:
        cfg = json.loads(feed.config_json or "{}")
    except Exception:
        cfg = {}
    base_url = cfg.get("url", "").rstrip("/")
    if not base_url:
        raise ValueError("MISP feed requires config_json.url")

    _MISP_TYPE_MAP = {
        "ip-src": "ip", "ip-dst": "ip",
        "domain": "domain", "hostname": "domain",
        "url": "url",
        "md5": "hash", "sha256": "hash", "sha1": "hash",
        "vulnerability": "cve",
    }

    # Build timestamp filter
    ts = "0"
    if feed.last_polled_at:
        lp = feed.last_polled_at
        if lp.tzinfo is None:
            lp = lp.replace(tzinfo=timezone.utc)
        ts = str(int(lp.timestamp()))

    headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
    total = 0
    page = 1

    async with httpx.AsyncClient(timeout=30, headers=headers, verify=cfg.get("verify_ssl", True)) as client:
        while True:
            body = {"returnFormat": "json", "limit": 1000, "page": page, "timestamp": ts}
            r = await client.post(f"{base_url}/attributes/restSearch", json=body)
            r.raise_for_status()
            data = r.json()
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                break
            for attr in attrs:
                itype_raw = attr.get("type", "")
                itype = _MISP_TYPE_MAP.get(itype_raw)
                if not itype:
                    continue
                val = attr.get("value", "")
                if not val:
                    continue
                # Severity from to_ids and threat level
                to_ids = attr.get("to_ids", False)
                event_tl = attr.get("Event", {}).get("threat_level_id", "4")
                try:
                    tl = int(event_tl)
                except Exception:
                    tl = 4
                if to_ids and tl == 1:
                    severity = "high"
                elif to_ids:
                    severity = "medium"
                else:
                    severity = "low"
                is_new = _upsert_indicator(
                    db, feed.id, itype, val,
                    severity=severity,
                    source_ref=attr.get("uuid", ""),
                    confidence=60 if to_ids else 30,
                )
                if is_new:
                    total += 1
            if len(attrs) < 1000:
                break
            page += 1

    db.flush()
    logger.info("MISP: %d new indicators", total)
    return total


async def _fetch_taxii(feed: ThreatIntelFeed, db) -> int:
    """Minimal TAXII 2.1 client — fetches STIX 2.1 indicators."""
    api_key = decrypt_value(feed.encrypted_api_key or "")
    try:
        cfg = json.loads(feed.config_json or "{}")
    except Exception:
        cfg = {}
    base_url = cfg.get("url", "").rstrip("/")
    if not base_url:
        raise ValueError("TAXII feed requires config_json.url")
    collection_id = cfg.get("collection_id", "")

    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    auth = None
    if cfg.get("username") and cfg.get("password"):
        auth = (cfg["username"], cfg["password"])

    # Pattern extractors
    _IPV4_RE = re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE)
    _DOMAIN_RE = re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]", re.IGNORECASE)
    _URL_RE = re.compile(r"\[url:value\s*=\s*'([^']+)'\]", re.IGNORECASE)
    _HASH_RE = re.compile(r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]", re.IGNORECASE)

    added_after = ""
    if feed.last_polled_at:
        lp = feed.last_polled_at
        if lp.tzinfo is None:
            lp = lp.replace(tzinfo=timezone.utc)
        added_after = lp.strftime("%Y-%m-%dT%H:%M:%SZ")

    total = 0

    async with httpx.AsyncClient(timeout=30, headers=headers, auth=auth, verify=cfg.get("verify_ssl", True)) as client:
        # Discovery → api root
        disc = await client.get(f"{base_url}/taxii/")
        disc.raise_for_status()
        disc_data = disc.json()
        api_roots = disc_data.get("api_roots", [base_url])
        api_root = api_roots[0].rstrip("/") if api_roots else base_url

        # Determine collection URL
        if collection_id:
            col_url = f"{api_root}/collections/{collection_id}"
        else:
            cols_r = await client.get(f"{api_root}/collections/")
            cols_r.raise_for_status()
            cols = cols_r.json().get("collections", [])
            if not cols:
                return 0
            col_url = f"{api_root}/collections/{cols[0]['id']}"

        # Fetch objects
        params = {"match[type]": "indicator"}
        if added_after:
            params["added_after"] = added_after
        obj_url = f"{col_url}/objects/"
        while obj_url:
            r = await client.get(obj_url, params=params)
            r.raise_for_status()
            obj_data = r.json()
            for obj in obj_data.get("objects", []):
                if obj.get("type") != "indicator":
                    continue
                pattern = obj.get("pattern", "")
                confidence = obj.get("confidence", 50)
                if confidence > 75:
                    severity = "high"
                elif confidence > 50:
                    severity = "medium"
                else:
                    severity = "low"
                stix_id = obj.get("id", "")

                for m in _IPV4_RE.findall(pattern):
                    if _upsert_indicator(db, feed.id, "ip", m, severity=severity, source_ref=stix_id, confidence=confidence):
                        total += 1
                for m in _DOMAIN_RE.findall(pattern):
                    if _upsert_indicator(db, feed.id, "domain", m, severity=severity, source_ref=stix_id, confidence=confidence):
                        total += 1
                for m in _URL_RE.findall(pattern):
                    if _upsert_indicator(db, feed.id, "url", m, severity=severity, source_ref=stix_id, confidence=confidence):
                        total += 1
                for m in _HASH_RE.findall(pattern):
                    if _upsert_indicator(db, feed.id, "hash", m, severity=severity, source_ref=stix_id, confidence=confidence):
                        total += 1

            # TAXII pagination via X-TAXII-Date-Added-Last or next link
            next_url = obj_data.get("next")
            obj_url = next_url if next_url else None
            params = {}  # next URL includes its own params

    db.flush()
    logger.info("TAXII: %d new indicators", total)
    return total


# ── Feed dispatcher ────────────────────────────────────────────────────────────

_FETCHERS = {
    "cisa_kev": _fetch_cisa_kev,
    "otx": _fetch_otx,
    "misp": _fetch_misp,
    "taxii": _fetch_taxii,
}


# ── Polling loop ───────────────────────────────────────────────────────────────

async def run_threat_intel_poller():
    """Background loop: poll each enabled feed according to its schedule."""
    logger.info("Threat intel poller started")
    while True:
        try:
            db = SessionLocal()
            try:
                now = datetime.now(timezone.utc)
                feeds = db.query(ThreatIntelFeed).filter_by(enabled=True).all()
                for feed in feeds:
                    # Check if due for polling
                    if feed.last_polled_at is not None:
                        lp = feed.last_polled_at
                        if lp.tzinfo is None:
                            lp = lp.replace(tzinfo=timezone.utc)
                        interval_minutes = feed.poll_interval_minutes or 60
                        from datetime import timedelta
                        if (now - lp).total_seconds() < interval_minutes * 60:
                            continue

                    fetcher = _FETCHERS.get(feed.feed_type)
                    if not fetcher:
                        logger.warning("Unknown feed type: %s", feed.feed_type)
                        continue

                    logger.info("Polling feed: %s (%s)", feed.name, feed.feed_type)
                    try:
                        count = await fetcher(feed, db)
                        feed.last_polled_at = datetime.now(timezone.utc)
                        feed.last_error = None
                        # Update indicator count
                        feed.indicator_count = db.query(ThreatIndicator).filter_by(feed_id=feed.id).count()
                        db.commit()
                        logger.info("Feed '%s' polled: %d total indicators", feed.name, feed.indicator_count)
                    except Exception as exc:
                        logger.warning("Feed '%s' poll error: %s", feed.name, exc)
                        feed.last_polled_at = datetime.now(timezone.utc)
                        feed.last_error = str(exc)
                        db.commit()
            finally:
                db.close()
        except asyncio.CancelledError:
            logger.info("Threat intel poller cancelled")
            return
        except Exception as exc:
            logger.error("Threat intel poller loop error: %s", exc)

        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            return


# ── IOC matching ───────────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _lookup_ip(db, ip: str):
    return (
        db.query(ThreatIndicator)
        .filter_by(indicator_type="ip", value=ip)
        .order_by(ThreatIndicator.id)
        .all()
    )


def _lookup_domain(db, domain: str):
    return (
        db.query(ThreatIndicator)
        .filter_by(indicator_type="domain", value=domain)
        .order_by(ThreatIndicator.id)
        .all()
    )


def _lookup_cve(db, cve: str):
    return (
        db.query(ThreatIndicator)
        .filter_by(indicator_type="cve", value=cve.upper())
        .order_by(ThreatIndicator.id)
        .all()
    )


async def _notify_ioc_match(ioc_match: IocMatch, indicator: ThreatIndicator):
    """Send webhook/email notifications for critical/high severity IOC matches."""
    webhook_url = get_service_setting("ioc_notify_webhook")
    email_to = get_service_setting("ioc_notify_email")

    if not webhook_url and not email_to:
        return

    payload = {
        "event": "ioc_match",
        "severity": ioc_match.severity,
        "matched_field": ioc_match.matched_field,
        "matched_value": ioc_match.matched_value,
        "indicator_type": indicator.indicator_type,
        "entry_id": ioc_match.entry_id,
        "matched_at": ioc_match.matched_at.isoformat() if ioc_match.matched_at else None,
        "tags": json.loads(indicator.tags_json or "[]"),
        "source_ref": indicator.source_ref,
    }

    if webhook_url:
        try:
            from alert_engine import _send_webhook
            await _send_webhook(webhook_url, payload)
        except Exception as exc:
            logger.warning("IOC match webhook failed: %s", exc)

    if email_to:
        subject = f"[SIEM] IOC Match: {ioc_match.severity.upper()} — {ioc_match.matched_value}"
        body = (
            f"IOC Match Detected\n"
            f"Severity: {ioc_match.severity}\n"
            f"Field: {ioc_match.matched_field}\n"
            f"Value: {ioc_match.matched_value}\n"
            f"Indicator type: {indicator.indicator_type}\n"
            f"Source: {indicator.source_ref or 'unknown'}\n"
            f"Entry ID: {ioc_match.entry_id}\n"
            f"Tags: {', '.join(json.loads(indicator.tags_json or '[]'))}\n"
            f"Time: {payload['matched_at']}\n"
        )
        try:
            from alert_engine import _send_email
            await _send_email(email_to, subject, body)
        except Exception as exc:
            logger.warning("IOC match email failed: %s", exc)


def _process_entry_iocs(db, entry: SyslogEntry) -> list:
    """Check a single SyslogEntry against all threat indicators. Returns IocMatch records."""
    matches = []
    now = datetime.now(timezone.utc)

    def _make_match(ind: ThreatIndicator, field: str, value: str) -> IocMatch:
        sev = ind.severity or "low"
        return IocMatch(
            indicator_id=ind.id,
            entry_id=entry.id,
            matched_field=field,
            matched_value=value,
            matched_at=now,
            severity=sev,
            acknowledged=False,
            notified=False,
        )

    # IP checks
    for field, ip_val in (("src_ip", entry.src_ip), ("dst_ip", entry.dst_ip)):
        if not ip_val:
            continue
        for ind in _lookup_ip(db, ip_val):
            matches.append(_make_match(ind, field, ip_val))

    # Domain checks
    for field, dom_val in (("hostname", entry.hostname), ("domain", entry.domain)):
        if not dom_val:
            continue
        for ind in _lookup_domain(db, dom_val):
            matches.append(_make_match(ind, field, dom_val))

    # CVE checks in message
    if entry.message:
        for cve in set(_CVE_RE.findall(entry.message)):
            for ind in _lookup_cve(db, cve.upper()):
                matches.append(_make_match(ind, "message", cve.upper()))

    return matches


async def run_ioc_matcher():
    """Background loop: scan new SyslogEntry rows for IOC matches."""
    logger.info("IOC matcher started")
    while True:
        try:
            db = SessionLocal()
            try:
                last_id_str = get_service_setting("ioc_matcher_last_id", db=db)
                last_id = int(last_id_str) if last_id_str else 0

                entries = (
                    db.query(SyslogEntry)
                    .filter(SyslogEntry.id > last_id)
                    .order_by(SyslogEntry.id)
                    .limit(500)
                    .all()
                )

                if not entries:
                    db.close()
                    await asyncio.sleep(60)
                    continue

                notify_queue = []
                for entry in entries:
                    ioc_matches = _process_entry_iocs(db, entry)
                    for m in ioc_matches:
                        db.add(m)
                        # Collect high/critical for notification
                        if m.severity in ("critical", "high"):
                            notify_queue.append(m)

                new_last_id = entries[-1].id
                set_service_setting("ioc_matcher_last_id", str(new_last_id), db=db)
                db.commit()

                if ioc_matches:
                    logger.info("IOC matcher: processed %d entries, %d total matches", len(entries), len(ioc_matches))

                # Reload matches to get IDs, then notify
                for m in notify_queue:
                    if m.id and not m.notified:
                        ind = db.query(ThreatIndicator).filter_by(id=m.indicator_id).first()
                        if ind:
                            await _notify_ioc_match(m, ind)
                            m.notified = True
                if notify_queue:
                    db.commit()

            finally:
                db.close()

        except asyncio.CancelledError:
            logger.info("IOC matcher cancelled")
            return
        except Exception as exc:
            logger.error("IOC matcher error: %s", exc)

        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            return


# ── Enrichment integration ────────────────────────────────────────────────────

def check_threat_intel(ip: str, db) -> Optional[dict]:
    """
    Look up a given IP in the threat indicators table.
    Returns the highest-severity match as a dict, or None.
    """
    inds = db.query(ThreatIndicator).filter_by(indicator_type="ip", value=ip).all()
    if not inds:
        return None
    # Return the highest severity indicator
    best = max(inds, key=lambda i: _SEV_ORDER.get(i.severity, 0))
    return {
        "indicator_id": best.id,
        "feed_id": best.feed_id,
        "indicator_type": best.indicator_type,
        "severity": best.severity,
        "confidence": best.confidence,
        "tags": json.loads(best.tags_json or "[]"),
        "source_ref": best.source_ref,
        "first_seen": best.first_seen.isoformat() if best.first_seen else None,
        "last_seen": best.last_seen.isoformat() if best.last_seen else None,
    }
