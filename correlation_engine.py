"""
Phase 4 — Alert Correlation / Fusion into Incidents.

Runs every 60 seconds and groups DetectionMatch, IocMatch, and AlertEvent
rows into Incident records based on shared entities within a sliding time
window (default 2 hours, tunable via 'correlation_window_hours' setting).
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from database import (
    AlertEvent, DetectionMatch, Incident, IncidentItem,
    Investigation, IocMatch, SessionLocal,
    get_service_setting, set_service_setting,
)
from alert_engine import _send_webhook, _send_email

logger = logging.getLogger("correlation_engine")

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ── Entity extraction ──────────────────────────────────────────────────────────

def _extract_entities_from_detection_match(match: DetectionMatch, entry) -> dict:
    ips, domains, users, hosts = [], [], [], []
    if entry:
        if entry.src_ip:
            ips.append(entry.src_ip)
        if entry.dst_ip:
            ips.append(entry.dst_ip)
        if entry.domain:
            domains.append(entry.domain)
        if entry.norm_hostname:
            hosts.append(entry.norm_hostname)
            domains.append(entry.norm_hostname)
        if entry.hostname:
            hosts.append(entry.hostname)
        if entry.norm_user:
            users.append(entry.norm_user)
    return {
        "ips": list(dict.fromkeys(filter(None, ips))),
        "domains": list(dict.fromkeys(filter(None, domains))),
        "users": list(dict.fromkeys(filter(None, users))),
        "hosts": list(dict.fromkeys(filter(None, hosts))),
    }


def _extract_entities_from_ioc_match(ioc_match: IocMatch) -> dict:
    ips, domains, users, hosts = [], [], [], []
    field = ioc_match.matched_field or ""
    value = ioc_match.matched_value or ""
    if field in ("src_ip", "dst_ip"):
        ips.append(value)
    elif field in ("domain", "hostname", "norm_hostname"):
        domains.append(value)
        hosts.append(value)
    return {
        "ips": list(filter(None, ips)),
        "domains": list(filter(None, domains)),
        "users": list(filter(None, users)),
        "hosts": list(filter(None, hosts)),
    }


def _extract_entities_from_alert(alert: AlertEvent) -> dict:
    """AlertEvent has rule_name and detail (text). Try to pull IPs from detail."""
    ips = []
    try:
        detail = alert.detail or ""
        import re
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", detail)
        ips = list(dict.fromkeys(found))
    except Exception:
        pass
    return {"ips": ips, "domains": [], "users": [], "hosts": []}


def _entity_keys(entities: dict) -> set:
    keys = set()
    for ip in entities.get("ips", []):
        keys.add(f"ip:{ip}")
    for d in entities.get("domains", []):
        keys.add(f"domain:{d}")
    for u in entities.get("users", []):
        keys.add(f"user:{u}")
    for h in entities.get("hosts", []):
        keys.add(f"host:{h}")
    return keys


def _primary_entity_key(entity_keys: set) -> str:
    """Return the most interesting entity key for display purposes."""
    for prefix in ("ip:", "domain:", "user:", "host:"):
        for k in sorted(entity_keys):
            if k.startswith(prefix):
                return k
    return next(iter(entity_keys), "unknown")


def _merge_entities(a: dict, b: dict) -> dict:
    result = {}
    for key in ("ips", "domains", "users", "hosts"):
        merged = list(dict.fromkeys((a.get(key) or []) + (b.get(key) or [])))
        result[key] = merged
    return result


def _entities_from_json(json_str: Optional[str]) -> dict:
    try:
        if json_str:
            return json.loads(json_str)
    except Exception:
        pass
    return {"ips": [], "domains": [], "users": [], "hosts": []}


def _escalate_severity(current: str, new: str) -> str:
    return new if _SEVERITY_ORDER.get(new, 0) > _SEVERITY_ORDER.get(current, 0) else current


# ── Core correlation ───────────────────────────────────────────────────────────

def _find_or_create_incident(
    db,
    entity_keys: set,
    severity: str,
    first_seen: datetime,
    mitre_techniques: list,
) -> Incident:
    window_hours = int(get_service_setting("correlation_window_hours", "2", db=db) or 2)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    # Search for existing open incident with matching entity
    existing_incident = None
    if entity_keys:
        for ek in entity_keys:
            item = (
                db.query(IncidentItem)
                .filter(IncidentItem.entity_key == ek)
                .join(
                    Incident,
                    Incident.id == IncidentItem.incident_id,
                )
                .filter(
                    Incident.status.in_(["open", "investigating"]),
                    Incident.last_seen >= cutoff,
                )
                .first()
            )
            if item:
                existing_incident = db.query(Incident).filter_by(id=item.incident_id).first()
                if existing_incident:
                    break

    if existing_incident:
        inc = existing_incident
        # Update last_seen
        inc.last_seen = datetime.now(timezone.utc)
        # Severity escalation only
        inc.severity = _escalate_severity(inc.severity, severity)
        # Union MITRE techniques
        existing_techniques = set()
        try:
            if inc.mitre_techniques_json:
                existing_techniques = set(json.loads(inc.mitre_techniques_json))
        except Exception:
            pass
        new_techniques = existing_techniques | set(mitre_techniques or [])
        inc.mitre_techniques_json = json.dumps(list(new_techniques))
        # Merge entities
        old_entities = _entities_from_json(inc.entities_json)
        new_entity_dict = _entity_keys_to_dict(entity_keys)
        merged = _merge_entities(old_entities, new_entity_dict)
        inc.entities_json = json.dumps(merged)
        inc.updated_at = datetime.now(timezone.utc)
        return inc

    # Create new incident
    primary = _primary_entity_key(entity_keys)
    label = primary.replace(":", ": ", 1) if ":" in primary else primary
    severity_label = severity.capitalize()
    title = f"{severity_label} Severity Incident — {label}"
    now = datetime.now(timezone.utc)
    entity_dict = _entity_keys_to_dict(entity_keys)
    inc = Incident(
        title=title,
        severity=severity,
        status="open",
        confidence=40,
        first_seen=first_seen or now,
        last_seen=now,
        entities_json=json.dumps(entity_dict),
        mitre_techniques_json=json.dumps(list(mitre_techniques or [])),
        item_count=0,
        source_diversity=1,
        created_at=now,
        updated_at=now,
    )
    db.add(inc)
    db.flush()  # get id
    return inc


def _entity_keys_to_dict(entity_keys: set) -> dict:
    result = {"ips": [], "domains": [], "users": [], "hosts": []}
    for k in entity_keys:
        if k.startswith("ip:"):
            result["ips"].append(k[3:])
        elif k.startswith("domain:"):
            result["domains"].append(k[7:])
        elif k.startswith("user:"):
            result["users"].append(k[5:])
        elif k.startswith("host:"):
            result["hosts"].append(k[5:])
    return result


def _add_item(db, incident: Incident, item_type: str, item_id: int, entity_key: str, severity: str) -> bool:
    """Add IncidentItem, skipping duplicates. Returns True if added."""
    from sqlalchemy.exc import IntegrityError
    existing = db.query(IncidentItem).filter_by(
        incident_id=incident.id, item_type=item_type, item_id=item_id
    ).first()
    if existing:
        return False
    item = IncidentItem(
        incident_id=incident.id,
        item_type=item_type,
        item_id=item_id,
        entity_key=entity_key,
        severity=severity,
        added_at=datetime.now(timezone.utc),
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return False
    return True


def _update_source_diversity_and_count(db, incident: Incident):
    items = db.query(IncidentItem).filter_by(incident_id=incident.id).all()
    incident.item_count = len(items)
    distinct_types = {i.item_type for i in items} - {"investigation"}
    incident.source_diversity = max(1, len(distinct_types))


def _score_incident(incident: Incident, db) -> int:
    score = 40
    # Source diversity bonus
    if incident.source_diversity > 1:
        score += 10 * (incident.source_diversity - 1)
    # Severity bonus
    if incident.severity == "critical":
        score += 10
    elif incident.severity == "high":
        score += 5
    # Investigation verdict bonus
    inv_items = db.query(IncidentItem).filter_by(
        incident_id=incident.id, item_type="investigation"
    ).all()
    for ii in inv_items:
        inv = db.query(Investigation).filter_by(id=ii.item_id).first()
        if inv:
            if inv.verdict in ("true_positive", "malicious"):
                score += 15
            elif inv.verdict in ("suspicious",):
                score += 10
    # MITRE techniques bonus
    try:
        techs = json.loads(incident.mitre_techniques_json or "[]")
        score += min(20, 5 * len(techs))
    except Exception:
        pass
    score = min(95, score)
    incident.confidence = score
    incident.updated_at = datetime.now(timezone.utc)
    return score


# ── Main loop ──────────────────────────────────────────────────────────────────

async def run_correlation_engine():
    logger.info("Correlation engine started.")
    await asyncio.sleep(15)  # let other services start first

    while True:
        try:
            await asyncio.to_thread(_run_correlation_cycle)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Correlation cycle error: %s", exc, exc_info=True)
        await asyncio.sleep(60)


def _run_correlation_cycle():
    db = SessionLocal()
    try:
        last_detection_id = int(get_service_setting("correlation_last_detection_id", "0", db=db) or 0)
        last_ioc_id = int(get_service_setting("correlation_last_ioc_id", "0", db=db) or 0)
        last_alert_id = int(get_service_setting("correlation_last_alert_id", "0", db=db) or 0)

        new_last_detection_id = last_detection_id
        new_last_ioc_id = last_ioc_id
        new_last_alert_id = last_alert_id

        # ── 1. Process DetectionMatch rows ────────────────────────────────────
        detection_matches = (
            db.query(DetectionMatch)
            .filter(
                DetectionMatch.id > last_detection_id,
                DetectionMatch.severity.in_(["critical", "high", "medium"]),
            )
            .order_by(DetectionMatch.id.asc())
            .limit(200)
            .all()
        )

        for match in detection_matches:
            try:
                from database import SyslogEntry
                entry = db.query(SyslogEntry).filter_by(id=match.entry_id).first()
                entities = _extract_entities_from_detection_match(match, entry)
                ek = _entity_keys(entities)
                techs = []
                try:
                    techs = json.loads(match.mitre_techniques_json or "[]")
                except Exception:
                    pass
                first_seen = match.matched_at or datetime.now(timezone.utc)
                if ek:
                    inc = _find_or_create_incident(db, ek, match.severity, first_seen, techs)
                    primary = _primary_entity_key(ek)
                    added = _add_item(db, inc, "detection_match", match.id, primary, match.severity)
                    if added:
                        _update_source_diversity_and_count(db, inc)
                        _score_incident(inc, db)
            except Exception as e:
                logger.debug("Error processing detection_match %d: %s", match.id, e)
            new_last_detection_id = max(new_last_detection_id, match.id)

        # ── 2. Process IocMatch rows ──────────────────────────────────────────
        ioc_matches = (
            db.query(IocMatch)
            .filter(
                IocMatch.id > last_ioc_id,
                IocMatch.severity.in_(["critical", "high"]),
            )
            .order_by(IocMatch.id.asc())
            .limit(100)
            .all()
        )

        for ioc in ioc_matches:
            try:
                entities = _extract_entities_from_ioc_match(ioc)
                ek = _entity_keys(entities)
                first_seen = ioc.matched_at or datetime.now(timezone.utc)
                if ek:
                    inc = _find_or_create_incident(db, ek, ioc.severity, first_seen, [])
                    primary = _primary_entity_key(ek)
                    added = _add_item(db, inc, "ioc_match", ioc.id, primary, ioc.severity)
                    if added:
                        _update_source_diversity_and_count(db, inc)
                        _score_incident(inc, db)
            except Exception as e:
                logger.debug("Error processing ioc_match %d: %s", ioc.id, e)
            new_last_ioc_id = max(new_last_ioc_id, ioc.id)

        # ── 3. Process AlertEvent rows ────────────────────────────────────────
        try:
            alert_events = (
                db.query(AlertEvent)
                .filter(AlertEvent.id > last_alert_id)
                .order_by(AlertEvent.id.asc())
                .limit(100)
                .all()
            )
            for alert in alert_events:
                try:
                    entities = _extract_entities_from_alert(alert)
                    ek = _entity_keys(entities)
                    first_seen = alert.fired_at or datetime.now(timezone.utc)
                    if ek:
                        inc = _find_or_create_incident(db, ek, "medium", first_seen, [])
                        primary = _primary_entity_key(ek)
                        added = _add_item(db, inc, "alert_event", alert.id, primary, "medium")
                        if added:
                            _update_source_diversity_and_count(db, inc)
                            _score_incident(inc, db)
                except Exception as e:
                    logger.debug("Error processing alert_event %d: %s", alert.id, e)
                new_last_alert_id = max(new_last_alert_id, alert.id)
        except Exception as e:
            logger.debug("AlertEvent processing skipped: %s", e)

        # ── 4. Link completed Investigations to Incidents ─────────────────────
        try:
            recent_investigations = (
                db.query(Investigation)
                .filter(
                    Investigation.status == "complete",
                    Investigation.verdict.isnot(None),
                    Investigation.completed_at >= datetime.now(timezone.utc) - timedelta(minutes=5),
                )
                .all()
            )
            for inv in recent_investigations:
                # Find incident items whose item_id/type match this investigation's trigger
                trigger_type_map = {
                    "detection_match": "detection_match",
                    "ioc_match": "ioc_match",
                    "alert": "alert_event",
                }
                mapped_type = trigger_type_map.get(inv.trigger_type, inv.trigger_type)
                matching_items = (
                    db.query(IncidentItem)
                    .filter_by(item_id=inv.trigger_id, item_type=mapped_type)
                    .all()
                )
                affected_incident_ids = {i.incident_id for i in matching_items}
                for inc_id in affected_incident_ids:
                    inc = db.query(Incident).filter_by(id=inc_id).first()
                    if inc:
                        added = _add_item(db, inc, "investigation", inv.id, None, inv.severity or "medium")
                        if added:
                            _update_source_diversity_and_count(db, inc)
                            _score_incident(inc, db)
        except Exception as e:
            logger.debug("Investigation linking error: %s", e)

        db.commit()

        # ── 5. Notify on new high-confidence incidents ─────────────────────────
        try:
            notified_raw = get_service_setting("correlation_notified_incidents", "[]", db=db)
            notified_ids = set(json.loads(notified_raw))
        except Exception:
            notified_ids = set()

        high_conf_incidents = (
            db.query(Incident)
            .filter(
                Incident.confidence >= 70,
                Incident.severity.in_(["critical", "high"]),
                Incident.status.in_(["open", "investigating"]),
            )
            .all()
        )

        new_notified = set(notified_ids)
        for inc in high_conf_incidents:
            if inc.id not in notified_ids:
                _notify_incident(inc)
                new_notified.add(inc.id)

        if new_notified != notified_ids:
            set_service_setting("correlation_notified_incidents", json.dumps(list(new_notified)), db=db)
            db.commit()

        # ── 6. Advance high-water marks ───────────────────────────────────────
        if new_last_detection_id != last_detection_id:
            set_service_setting("correlation_last_detection_id", str(new_last_detection_id), db=db)
        if new_last_ioc_id != last_ioc_id:
            set_service_setting("correlation_last_ioc_id", str(new_last_ioc_id), db=db)
        if new_last_alert_id != last_alert_id:
            set_service_setting("correlation_last_alert_id", str(new_last_alert_id), db=db)
        db.commit()

    finally:
        db.close()


def _notify_incident(incident: Incident):
    """Fire webhook/email notification for a high-confidence incident."""
    import asyncio as _asyncio

    webhook_url = get_service_setting("incident_notify_webhook")
    email_to = get_service_setting("incident_notify_email")

    entities = {}
    try:
        entities = json.loads(incident.entities_json or "{}")
    except Exception:
        pass

    payload = {
        "event": "incident.high_confidence",
        "incident_id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "status": incident.status,
        "item_count": incident.item_count,
        "source_diversity": incident.source_diversity,
        "entities": entities,
        "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
        "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
    }

    subject = f"[SIEM] {incident.severity.upper()} Incident #{incident.id}: {incident.title}"
    body = (
        f"Incident #{incident.id}\n"
        f"Title: {incident.title}\n"
        f"Severity: {incident.severity}\n"
        f"Confidence: {incident.confidence}%\n"
        f"Items: {incident.item_count} | Source Diversity: {incident.source_diversity}\n"
        f"First seen: {incident.first_seen}\n"
        f"Last seen: {incident.last_seen}\n"
    )

    try:
        loop = _asyncio.get_event_loop()
        if webhook_url:
            loop.create_task(_send_webhook(webhook_url, payload))
        if email_to:
            loop.create_task(_send_email(email_to, subject, body))
    except RuntimeError:
        pass  # no event loop in sync context; skip notification
