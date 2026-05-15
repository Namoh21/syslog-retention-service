"""
Background alert rule evaluator.
Runs every 60 seconds, evaluates all enabled AlertRules,
fires notifications via webhook and/or email when conditions are met.
"""
import asyncio
import json
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

import httpx

from database import AlertEvent, AlertRule, SessionLocal, SyslogEntry, get_service_setting

logger = logging.getLogger("alert_engine")


# ── Rule evaluation ───────────────────────────────────────────────────────────

def _count_events(db, rule: AlertRule) -> tuple[int, list[SyslogEntry]]:
    """Count matching events in the rule's time window."""
    params = {}
    try:
        params = json.loads(rule.condition_params or "{}")
    except Exception:
        pass

    since = datetime.now(timezone.utc) - timedelta(minutes=rule.window_minutes)
    q = db.query(SyslogEntry).filter(SyslogEntry.received_at >= since)

    if rule.condition_type == "severity":
        max_sev = params.get("severity_max", 3)
        q = q.filter(SyslogEntry.severity <= max_sev)

    elif rule.condition_type == "pattern":
        pattern = params.get("pattern", "")
        if pattern:
            safe = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            q = q.filter(SyslogEntry.message.ilike(f"%{safe}%", escape="\\"))

    elif rule.condition_type == "threshold":
        event_type = params.get("event_type")
        src_ip = params.get("src_ip")
        action = params.get("action")
        dst_port = params.get("dst_port")
        if event_type:
            q = q.filter(SyslogEntry.event_type == event_type)
        if src_ip:
            q = q.filter(SyslogEntry.src_ip == src_ip)
        if action:
            q = q.filter(SyslogEntry.action == action.upper())
        if dst_port:
            q = q.filter(SyslogEntry.dst_port == int(dst_port))

    elif rule.condition_type == "new_ip":
        # Fires when an IP appears in the window that has never been seen before
        recent_ips = {r.source_ip for r in q.with_entities(SyslogEntry.source_ip).all()}
        ever_seen = {
            r.source_ip for r in
            db.query(SyslogEntry.source_ip)
            .filter(SyslogEntry.received_at < since)
            .filter(SyslogEntry.source_ip.isnot(None))
            .distinct()
            .all()
        }
        new_ips = recent_ips - ever_seen
        if new_ips:
            sample = q.filter(SyslogEntry.source_ip.in_(new_ips)).limit(5).all()
            return len(new_ips), sample
        return 0, []

    count = q.count()
    sample = q.order_by(SyslogEntry.received_at.desc()).limit(5).all() if count > 0 else []
    return count, sample


def _should_fire(rule: AlertRule) -> bool:
    if not rule.enabled:
        return False
    if rule.last_fired_at is None:
        return True
    last = rule.last_fired_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    # Clamp future timestamps (clock skew) so alerts don't get permanently stuck
    if last > now:
        last = now
    return now - last > timedelta(minutes=rule.cooldown_minutes)


def _build_detail(rule: AlertRule, count: int, sample: list) -> str:
    lines = [f"Alert: {rule.name}", f"Condition: {rule.condition_type}", f"Count: {count}"]
    for e in sample[:3]:
        ts = e.received_at.strftime("%H:%M:%S") if e.received_at else "?"
        lines.append(f"  [{ts}] {e.source_ip or '?'} → {e.event_type or ''} {e.message or ''}"[:120])
    return "\n".join(lines)


# ── Notification senders ──────────────────────────────────────────────────────

async def _send_webhook(url: str, payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json=payload)
        logger.info("Webhook sent for alert: %s", payload.get("rule"))
    except Exception as exc:
        logger.warning("Webhook failed (%s): %s", url, exc)


async def _send_email(to_addr: str, subject: str, body: str) -> None:
    smtp_host = get_service_setting("smtp_host")
    smtp_port = int(get_service_setting("smtp_port") or "587")
    smtp_user = get_service_setting("smtp_user")
    smtp_pass = get_service_setting("smtp_password")
    from_addr = get_service_setting("smtp_from") or smtp_user

    if not smtp_host or not to_addr:
        logger.debug("Email not configured — skipping notification to %s", to_addr)
        return
    try:
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.ehlo()
            if smtp_port != 25:
                s.starttls()
            if smtp_user and smtp_pass:
                s.login(smtp_user, smtp_pass)
            s.sendmail(from_addr, [to_addr], msg.as_string())
        logger.info("Alert email sent to %s: %s", to_addr, subject)
    except Exception as exc:
        logger.warning("Email notification failed: %s", exc)


# ── Main evaluation loop ──────────────────────────────────────────────────────

async def _evaluate_once() -> None:
    db = SessionLocal()
    try:
        rules = db.query(AlertRule).filter_by(enabled=True).all()
        for rule in rules:
            if not _should_fire(rule):
                continue
            count, sample = _count_events(db, rule)
            if count < rule.threshold:
                continue

            detail = _build_detail(rule, count, sample)
            event = AlertEvent(rule_id=rule.id, rule_name=rule.name, detail=detail)
            db.add(event)
            rule.last_fired_at = datetime.now(timezone.utc)
            db.commit()

            logger.info("Alert fired: %s (count=%d)", rule.name, count)

            # Notifications
            payload = {
                "rule": rule.name,
                "condition": rule.condition_type,
                "count": count,
                "detail": detail,
                "fired_at": datetime.now(timezone.utc).isoformat(),
            }
            tasks = []
            if rule.notify_webhook:
                tasks.append(_send_webhook(rule.notify_webhook, payload))
            if rule.notify_email:
                tasks.append(_send_email(
                    rule.notify_email,
                    f"[SIEM Alert] {rule.name}",
                    detail,
                ))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as exc:
        logger.error("Alert evaluation error: %s", exc)
    finally:
        db.close()


async def run_alert_engine() -> None:
    """Long-running background task — evaluates all alert rules every 60 seconds."""
    logger.info("Alert engine started")
    while True:
        await asyncio.sleep(60)
        await _evaluate_once()


# ── Daily digest ──────────────────────────────────────────────────────────────

async def send_daily_digest(to_email: str) -> dict:
    """Generate a 24h AI security summary and email it."""
    from database import query_logs
    from ai_analysis import analyze_logs

    db = SessionLocal()
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        entries, total = query_logs(db, since=since, limit=500)
        if not entries:
            return {"sent": False, "reason": "No log entries in last 24 hours"}

        result = await analyze_logs(entries, focus="daily security summary", hours=24)
        analysis = result.get("analysis", {})
        if isinstance(analysis, dict):
            summary = analysis.get("summary", "No summary available.")
            threat_level = analysis.get("threat_level", "UNKNOWN")
            immediate = "\n".join(f"• {a}" for a in analysis.get("immediate_actions", []))
        else:
            summary = str(analysis)
            threat_level = "UNKNOWN"
            immediate = ""

        body = f"""SIEM Daily Security Digest
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
Threat Level: {threat_level}
Log Entries Analyzed: {total}

SUMMARY
{summary}

{"IMMEDIATE ACTIONS" + chr(10) + immediate if immediate else ""}

--
Syslog Retention & SIEM Service
"""
        await _send_email(to_email, f"[SIEM Daily Digest] {datetime.now(timezone.utc).strftime('%Y-%m-%d')} — Threat Level: {threat_level}", body)
        return {"sent": True, "threat_level": threat_level, "log_count": total}
    finally:
        db.close()
