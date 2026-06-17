"""
Detection Engine — evaluates YAML-defined rules against SyslogEntry records.
Runs every 30 seconds, creates DetectionMatch rows, and sends notifications
for high/critical severity matches.
"""
import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from database import (
    DetectionMatch,
    DetectionRule,
    SessionLocal,
    SyslogEntry,
    get_service_setting,
    set_service_setting,
)

logger = logging.getLogger("detection_engine")

# ── MITRE reference ───────────────────────────────────────────────────────────

_MITRE_REF: Optional[dict] = None


def _load_mitre_reference() -> dict:
    global _MITRE_REF
    if _MITRE_REF is not None:
        return _MITRE_REF
    ref_path = Path(__file__).parent / "data" / "mitre_attack.json"
    try:
        with ref_path.open(encoding="utf-8") as f:
            _MITRE_REF = json.load(f)
    except Exception as exc:
        logger.warning("Could not load MITRE reference: %s", exc)
        _MITRE_REF = {"tactics": {}, "techniques": {}}
    return _MITRE_REF


def resolve_technique(tech_id: str) -> Optional[dict]:
    """Return {"id": ..., "name": ..., "tactics": [...]} or None."""
    ref = _load_mitre_reference()
    tid = tech_id.upper()
    tech = ref.get("techniques", {}).get(tid)
    if not tech:
        return None
    tactics_map = ref.get("tactics", {})
    return {
        "id": tid,
        "name": tech["name"],
        "tactics": [
            {"id": t, "name": tactics_map.get(t, t)}
            for t in tech.get("tactics", [])
        ],
    }


# ── Rule sync ─────────────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _parse_yaml_rule(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a mapping")
    rule_id = str(data.get("id") or "").strip()
    name = str(data.get("name") or "").strip()
    if not rule_id or not name:
        raise ValueError("Rule missing 'id' or 'name'")

    detection = data.get("detection") or {}
    match_node = detection.get("match")
    aggregate_node = detection.get("aggregate")

    condition = {}
    if match_node:
        condition["match"] = match_node
    if aggregate_node:
        condition["aggregate"] = aggregate_node

    tags = data.get("tags") or []
    false_positives = data.get("false_positives") or []

    return {
        "rule_id": rule_id,
        "name": name,
        "description": str(data.get("description") or ""),
        "severity": str(data.get("severity") or "medium").lower(),
        "category": str(data.get("category") or ""),
        "tags_json": json.dumps(tags),
        "condition_json": json.dumps(condition),
        "false_positives_json": json.dumps(false_positives),
        "enabled": bool(data.get("enabled", True)),
        "author": str(data.get("author") or ""),
        "version": str(data.get("version") or ""),
    }


def sync_rules_from_disk(db) -> dict:
    """Walk detections/**/*.yaml, parse, upsert by rule_id. Returns summary dict."""
    base = Path(__file__).parent / "detections"
    if not base.exists():
        return {"loaded": 0, "updated": 0, "errors": []}

    loaded = 0
    updated = 0
    errors = []

    for yaml_path in sorted(base.rglob("*.yaml")):
        try:
            file_hash = _sha256_file(yaml_path)
            rule_data = _parse_yaml_rule(yaml_path)
            rule_id = rule_data["rule_id"]

            existing = db.query(DetectionRule).filter_by(rule_id=rule_id).first()
            now = datetime.now(timezone.utc)

            if existing:
                if existing.file_hash == file_hash:
                    loaded += 1
                    continue
                # Update changed fields
                for k, v in rule_data.items():
                    setattr(existing, k, v)
                existing.source_file = str(yaml_path)
                existing.file_hash = file_hash
                existing.last_synced_at = now
                existing.updated_at = now
                updated += 1
            else:
                rule = DetectionRule(
                    source_file=str(yaml_path),
                    file_hash=file_hash,
                    last_synced_at=now,
                    **rule_data,
                )
                db.add(rule)
                loaded += 1
        except Exception as exc:
            errors.append({"file": str(yaml_path), "error": str(exc)})
            logger.warning("Error loading rule %s: %s", yaml_path, exc)

    db.commit()
    return {"loaded": loaded, "updated": updated, "errors": errors}


# ── Condition filter builder ──────────────────────────────────────────────────

# Map field names to SyslogEntry columns
_FIELD_MAP = {
    "event_type": SyslogEntry.event_type,
    "src_ip": SyslogEntry.src_ip,
    "dst_ip": SyslogEntry.dst_ip,
    "src_port": SyslogEntry.src_port,
    "dst_port": SyslogEntry.dst_port,
    "protocol": SyslogEntry.protocol,
    "action": SyslogEntry.action,
    "direction": SyslogEntry.direction,
    "interface_in": SyslogEntry.interface_in,
    "interface_out": SyslogEntry.interface_out,
    "mac_address": SyslogEntry.mac_address,
    "norm_user": SyslogEntry.norm_user,
    "norm_hostname": SyslogEntry.norm_hostname,
    "domain": SyslogEntry.domain,
    "url_category": SyslogEntry.url_category,
    "rule_name": SyslogEntry.rule_name,
    "severity": SyslogEntry.severity,
    "message": SyslogEntry.message,
    "hostname": SyslogEntry.hostname,
    "log_source_ip": SyslogEntry.log_source_ip,
    "app_name": SyslogEntry.app_name,
}


def _build_sqla_filter(node: Any, model=SyslogEntry):
    """
    Recursively translate a condition tree node into a SQLAlchemy filter expression.
    Returns None if no filter can be built (regex — handled in Python post-query).
    Returns a special dict {"_regex": (col, pattern)} for regex leaves.
    """
    from sqlalchemy import and_, or_, not_

    if not isinstance(node, dict):
        return None

    # Combinators
    if "and" in node:
        children = [_build_sqla_filter(c, model) for c in node["and"]]
        sql_parts = [c for c in children if c is not None and not isinstance(c, dict)]
        regex_parts = [c for c in children if isinstance(c, dict) and "_regex" in c]
        # If there are regex parts, we can only handle them post-query
        # Return the SQL parts combined and carry regex as a list
        result_filter = and_(*sql_parts) if sql_parts else None
        if regex_parts:
            return {"_and_filter": result_filter, "_regexes": regex_parts}
        return result_filter

    if "or" in node:
        children = [_build_sqla_filter(c, model) for c in node["or"]]
        sql_parts = [c for c in children if c is not None and not isinstance(c, dict)]
        if sql_parts:
            return or_(*sql_parts)
        return None

    if "not" in node:
        child = _build_sqla_filter(node["not"], model)
        if child is not None and not isinstance(child, dict):
            return not_(child)
        return None

    # Leaf node
    field_name = node.get("field")
    op = node.get("op")
    value = node.get("value")

    if not field_name or not op:
        return None

    col = _FIELD_MAP.get(field_name)
    if col is None:
        return None

    if op == "eq":
        return col == value
    elif op == "neq":
        return col != value
    elif op == "contains":
        return col.contains(str(value))
    elif op == "not_contains":
        return ~col.contains(str(value))
    elif op == "in":
        return col.in_(value if isinstance(value, list) else [value])
    elif op == "not_in":
        return col.notin_(value if isinstance(value, list) else [value])
    elif op == "gt":
        return col > value
    elif op == "gte":
        return col >= value
    elif op == "lt":
        return col < value
    elif op == "lte":
        return col <= value
    elif op == "exists":
        return col.isnot(None)
    elif op == "not_exists":
        return col.is_(None)
    elif op == "regex":
        # Collect candidates via SQL (no filter) then apply in Python
        return {"_regex": (col, str(value))}
    return None


def _apply_regex_filter(rows: list, regex_info: dict) -> list:
    """Filter rows by regex patterns extracted from the condition tree."""
    regexes = regex_info.get("_regexes", [])
    if not regexes:
        return rows

    def row_matches(row):
        for r in regexes:
            col_attr, pattern = r["_regex"]
            col_name = col_attr.key
            val = getattr(row, col_name, None)
            if val is None:
                return False
            if not re.search(pattern, str(val), re.IGNORECASE):
                return False
        return True

    return [r for r in rows if row_matches(r)]


# ── Notification helpers ──────────────────────────────────────────────────────

async def _notify_match(rule: DetectionRule, entries: list, match_ids: list[int]):
    """Send webhook/email notifications for high/critical matches."""
    try:
        from alert_engine import _send_webhook, _send_email
    except ImportError:
        return

    webhook_url = get_service_setting("detection_notify_webhook")
    email_addr = get_service_setting("detection_notify_email")

    if not webhook_url and not email_addr:
        return

    tags = json.loads(rule.tags_json or "[]")
    mitre = [t for t in tags if t.startswith("attack.t")]

    payload = {
        "alert_type": "detection_match",
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "category": rule.category,
        "match_count": len(match_ids),
        "mitre_techniques": mitre,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if webhook_url:
        await _send_webhook(webhook_url, payload)

    if email_addr:
        subject = f"[SIEM Detection] {rule.severity.upper()}: {rule.name}"
        body_lines = [
            f"Detection Rule Fired: {rule.name}",
            f"Rule ID: {rule.rule_id}",
            f"Severity: {rule.severity}",
            f"Category: {rule.category}",
            f"Matches: {len(match_ids)}",
            f"MITRE: {', '.join(mitre) if mitre else 'N/A'}",
            f"Time: {datetime.now(timezone.utc).isoformat()}",
        ]
        if entries:
            body_lines.append("\nSample entries:")
            for e in entries[:3]:
                ts = e.received_at.strftime("%H:%M:%S") if e.received_at else "?"
                body_lines.append(f"  [{ts}] {e.log_source_ip or '?'} {e.event_type or ''} {e.message or ''}"[:120])
        await _send_email(email_addr, subject, "\n".join(body_lines))


# ── Main engine loop ──────────────────────────────────────────────────────────

def _run_rules_sync(last_id: int) -> tuple[int, list[dict]]:
    """
    Synchronous rule evaluation. Returns (new_max_id, list of notification_payloads).
    Must be called in a thread pool.
    """
    db = SessionLocal()
    try:
        rules = db.query(DetectionRule).filter_by(enabled=True).all()
        if not rules:
            # Still advance high-water mark to latest entry
            latest = db.query(SyslogEntry.id).order_by(SyslogEntry.id.desc()).first()
            return (latest[0] if latest else last_id), []

        # Cap entries to process per cycle
        MAX_PER_RULE = 1000
        new_max_id = last_id
        notifications = []

        # Find global max id first
        latest = db.query(SyslogEntry.id).filter(SyslogEntry.id > last_id).order_by(SyslogEntry.id.desc()).first()
        if not latest:
            return last_id, []
        global_max = latest[0]

        for rule in rules:
            try:
                condition = json.loads(rule.condition_json or "{}")
                match_node = condition.get("match")
                aggregate = condition.get("aggregate")

                if not match_node:
                    continue

                # Build base query
                q = db.query(SyslogEntry).filter(SyslogEntry.id > last_id)

                # Build SQL filter
                filter_result = _build_sqla_filter(match_node)
                regex_info = None

                if isinstance(filter_result, dict):
                    if "_and_filter" in filter_result:
                        sql_filter = filter_result["_and_filter"]
                        regex_info = filter_result
                    elif "_regex" in filter_result:
                        sql_filter = None
                        regex_info = filter_result
                    else:
                        sql_filter = None
                else:
                    sql_filter = filter_result

                if sql_filter is not None:
                    q = q.filter(sql_filter)

                q = q.order_by(SyslogEntry.id).limit(MAX_PER_RULE)
                rows = q.all()

                # Apply regex post-filtering
                if regex_info:
                    rows = _apply_regex_filter(rows, regex_info)

                if not rows:
                    continue

                tags = json.loads(rule.tags_json or "[]")
                mitre_techniques = [t.replace("attack.", "").upper() for t in tags if t.startswith("attack.t")]

                match_ids = []
                now = datetime.now(timezone.utc)

                if aggregate:
                    # Aggregate: group_by + window + threshold
                    group_field = aggregate.get("group_by", "src_ip")
                    window_min = int(aggregate.get("window_minutes", 5))
                    threshold = int(aggregate.get("threshold", 10))

                    window_start = now - timedelta(minutes=window_min)

                    # Group rows by field value
                    from collections import defaultdict
                    groups: dict[str, list] = defaultdict(list)
                    for row in rows:
                        val = getattr(row, group_field, None) or "__none__"
                        # Only count rows within the time window
                        if row.received_at and row.received_at >= window_start:
                            groups[val].append(row)

                    for group_val, group_rows in groups.items():
                        if len(group_rows) < threshold:
                            continue

                        matched_fields = {group_field: group_val, "count": len(group_rows)}
                        dm = DetectionMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            rule_str_id=rule.rule_id,
                            entry_id=group_rows[-1].id,
                            matched_at=now,
                            severity=rule.severity,
                            mitre_techniques_json=json.dumps(mitre_techniques),
                            matched_fields_json=json.dumps(matched_fields),
                            entry_received_at=group_rows[-1].received_at,
                        )
                        db.add(dm)
                        match_ids.append(group_rows[-1].id)

                else:
                    # Simple: one DetectionMatch per row
                    for row in rows:
                        matched_fields = {}
                        for field_name in list(_FIELD_MAP.keys())[:8]:
                            val = getattr(row, field_name, None)
                            if val is not None:
                                matched_fields[field_name] = str(val)

                        dm = DetectionMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            rule_str_id=rule.rule_id,
                            entry_id=row.id,
                            matched_at=now,
                            severity=rule.severity,
                            mitre_techniques_json=json.dumps(mitre_techniques),
                            matched_fields_json=json.dumps(matched_fields),
                            entry_received_at=row.received_at,
                        )
                        db.add(dm)
                        match_ids.append(row.id)

                db.flush()

                if match_ids and rule.severity in ("critical", "high"):
                    last_match = (
                        db.query(DetectionMatch)
                        .filter_by(rule_id=rule.id)
                        .order_by(DetectionMatch.id.desc())
                        .first()
                    )
                    # Best-effort: get a representative matched value for the title
                    matched_value = ""
                    if rows:
                        matched_value = getattr(rows[-1], "src_ip", "") or getattr(rows[-1], "hostname", "") or ""
                    notifications.append({
                        "rule": rule,
                        "entries": rows[:5],
                        "match_ids": match_ids,
                        "last_match_id": last_match.id if last_match else None,
                        "matched_value": matched_value,
                    })

            except Exception as exc:
                logger.warning("Rule %s evaluation error: %s", rule.rule_id, exc)
                continue

        # Advance high-water mark
        new_max_id = global_max
        db.commit()
        return new_max_id, notifications

    finally:
        db.close()


async def run_detection_engine():
    """Async loop running every 30 seconds."""
    logger.info("Detection engine started.")
    while True:
        try:
            last_id_str = get_service_setting("detection_engine_last_id") or "0"
            last_id = int(last_id_str)

            new_max_id, notifications = await asyncio.to_thread(_run_rules_sync, last_id)

            if new_max_id > last_id:
                set_service_setting("detection_engine_last_id", str(new_max_id))

            for n in notifications:
                try:
                    await _notify_match(n["rule"], n["entries"], n["match_ids"])
                except Exception as exc:
                    logger.warning("Notification failed for rule %s: %s", n["rule"].rule_id, exc)
                try:
                    from agent_investigator import maybe_auto_investigate
                    from database import SessionLocal as _SL
                    _inv_db = _SL()
                    try:
                        rule = n["rule"]
                        mv = n.get("matched_value", "")
                        await maybe_auto_investigate(
                            trigger_type="detection_match",
                            trigger_id=n.get("last_match_id") or 0,
                            title=f"{rule.name}" + (f" — {mv}" if mv else ""),
                            severity=rule.severity,
                            context={"rule_id": rule.rule_id, "match_count": len(n["match_ids"])},
                            db=_inv_db,
                        )
                    finally:
                        _inv_db.close()
                except Exception as exc:
                    logger.warning("Auto-investigate trigger failed for rule %s: %s",
                                   n["rule"].rule_id, exc)

        except Exception as exc:
            logger.error("Detection engine cycle error: %s", exc, exc_info=True)

        await asyncio.sleep(30)
