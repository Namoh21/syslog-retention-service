"""
Phase 3 — AI Agent Investigation + Decision Ledger
Uses Claude tool-use (ReAct loop) to autonomously investigate security alerts.
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("agent_investigator")

# ── Tool definitions for Claude ───────────────────────────────────────────────

INVESTIGATOR_TOOLS = [
    {
        "name": "query_logs",
        "description": "Query syslog entries. Returns up to 50 matching log lines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "src_ip": {"type": "string", "description": "Filter by source IP"},
                "dst_ip": {"type": "string", "description": "Filter by destination IP"},
                "event_type": {"type": "string", "description": "Filter by event type (auth_failure, firewall_block, ids_alert, etc)"},
                "hostname": {"type": "string", "description": "Filter by hostname"},
                "since_minutes": {"type": "integer", "description": "Look back N minutes (default 60)"},
                "limit": {"type": "integer", "description": "Max results (default 20, max 50)"},
            },
        },
    },
    {
        "name": "enrich_ip",
        "description": "Get threat intelligence and geolocation for an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to enrich"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "lookup_ioc",
        "description": "Check if a value matches known threat indicators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "cve", "url"]},
                "value": {"type": "string"},
            },
            "required": ["indicator_type", "value"],
        },
    },
    {
        "name": "get_netflow",
        "description": "Query network flow records for an IP.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "since_minutes": {"type": "integer", "description": "Look back N minutes (default 60)"},
                "limit": {"type": "integer", "description": "Max results (default 20)"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "search_dns",
        "description": "Search DNS cache for queries to/from an IP or domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Source IP making DNS queries"},
                "domain": {"type": "string", "description": "Domain being queried"},
                "since_minutes": {"type": "integer", "description": "Look back N minutes (default 60)"},
            },
        },
    },
    {
        "name": "get_alert_history",
        "description": "Get recent alerts and detection matches for an entity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "src_ip": {"type": "string"},
                "hostname": {"type": "string"},
                "since_hours": {"type": "integer", "description": "Look back N hours (default 24)"},
            },
        },
    },
]


# ── Tool executor ─────────────────────────────────────────────────────────────

async def _execute_tool(tool_name: str, tool_input: dict, db) -> dict:
    """Dispatch a tool call and return results as a serializable dict."""
    try:
        if tool_name == "query_logs":
            return await _tool_query_logs(tool_input, db)
        elif tool_name == "enrich_ip":
            return await _tool_enrich_ip(tool_input)
        elif tool_name == "lookup_ioc":
            return _tool_lookup_ioc(tool_input, db)
        elif tool_name == "get_netflow":
            return _tool_get_netflow(tool_input, db)
        elif tool_name == "search_dns":
            return _tool_search_dns(tool_input, db)
        elif tool_name == "get_alert_history":
            return _tool_get_alert_history(tool_input, db)
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except Exception as exc:
        logger.warning("Tool '%s' execution error: %s", tool_name, exc)
        return {"error": str(exc)}


async def _tool_query_logs(inp: dict, db) -> dict:
    from database import SyslogEntry
    since_minutes = min(int(inp.get("since_minutes", 60)), 1440)
    limit = min(int(inp.get("limit", 20)), 50)
    since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    q = db.query(SyslogEntry).filter(SyslogEntry.received_at >= since)
    if inp.get("src_ip"):
        q = q.filter(SyslogEntry.src_ip == inp["src_ip"])
    if inp.get("dst_ip"):
        q = q.filter(SyslogEntry.dst_ip == inp["dst_ip"])
    if inp.get("event_type"):
        q = q.filter(SyslogEntry.event_type == inp["event_type"])
    if inp.get("hostname"):
        q = q.filter(SyslogEntry.hostname.ilike(f"%{inp['hostname']}%"))
    rows = q.order_by(SyslogEntry.received_at.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "entries": [
            {
                "id": e.id,
                "timestamp": e.received_at.isoformat() if e.received_at else None,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "event_type": e.event_type,
                "hostname": e.hostname,
                "message": (e.message or "")[:200],
                "severity": e.severity,
                "action": e.action,
                "protocol": e.protocol,
                "dst_port": e.dst_port,
            }
            for e in rows
        ],
    }


async def _tool_enrich_ip(inp: dict) -> dict:
    from enrichment import enrich_ip
    ip = inp.get("ip", "").strip()
    if not ip:
        return {"error": "ip is required"}
    result = await enrich_ip(ip)
    return result


def _tool_lookup_ioc(inp: dict, db) -> dict:
    from database import ThreatIndicator
    itype = inp.get("indicator_type", "")
    value = inp.get("value", "").strip()
    if not itype or not value:
        return {"error": "indicator_type and value are required"}
    rows = (
        db.query(ThreatIndicator)
        .filter_by(indicator_type=itype, value=value)
        .all()
    )
    return {
        "matched": len(rows) > 0,
        "count": len(rows),
        "indicators": [
            {
                "id": r.id,
                "feed_id": r.feed_id,
                "severity": r.severity,
                "confidence": r.confidence,
                "tags": json.loads(r.tags_json or "[]"),
                "source_ref": r.source_ref,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in rows
        ],
    }


def _tool_get_netflow(inp: dict, db) -> dict:
    try:
        from database import NetFlowRecord
    except ImportError:
        return {"error": "netflow not available"}
    ip = inp.get("ip", "").strip()
    if not ip:
        return {"error": "ip is required"}
    since_minutes = min(int(inp.get("since_minutes", 60)), 1440)
    limit = min(int(inp.get("limit", 20)), 100)
    since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    q = db.query(NetFlowRecord).filter(
        NetFlowRecord.received_at >= since,
        (NetFlowRecord.src_ip == ip) | (NetFlowRecord.dst_ip == ip),
    )
    rows = q.order_by(NetFlowRecord.received_at.desc()).limit(limit).all()
    if not rows:
        return {"count": 0, "flows": []}
    return {
        "count": len(rows),
        "flows": [
            {
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "proto_name": r.proto_name,
                "bytes": r.bytes,
                "packets": r.packets,
                "received_at": r.received_at.isoformat() if r.received_at else None,
                "domain": r.domain,
            }
            for r in rows
        ],
    }


def _tool_search_dns(inp: dict, db) -> dict:
    try:
        from database import DnsCache
    except ImportError:
        return {"error": "dns cache not available"}
    since_minutes = min(int(inp.get("since_minutes", 60)), 1440)
    since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    q = db.query(DnsCache).filter(DnsCache.recorded_at >= since)
    ip = inp.get("ip", "").strip()
    domain = inp.get("domain", "").strip()
    if not ip and not domain:
        return {"error": "ip or domain is required"}
    if ip:
        q = q.filter((DnsCache.resolved_ip == ip) | (DnsCache.client_ip == ip))
    if domain:
        q = q.filter(DnsCache.domain.ilike(f"%{domain}%"))
    rows = q.order_by(DnsCache.recorded_at.desc()).limit(50).all()
    return {
        "count": len(rows),
        "records": [
            {
                "domain": r.domain,
                "resolved_ip": r.resolved_ip,
                "client_ip": r.client_ip,
                "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
            }
            for r in rows
        ],
    }


def _tool_get_alert_history(inp: dict, db) -> dict:
    from database import AlertEvent, DetectionMatch
    since_hours = min(int(inp.get("since_hours", 24)), 168)
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    src_ip = inp.get("src_ip", "").strip()
    hostname = inp.get("hostname", "").strip()

    # DetectionMatches
    dm_q = db.query(DetectionMatch).filter(DetectionMatch.matched_at >= since)
    if src_ip:
        dm_q = dm_q.filter(DetectionMatch.matched_fields_json.contains(src_ip))
    matches = dm_q.order_by(DetectionMatch.matched_at.desc()).limit(20).all()

    # AlertEvents (by name heuristic)
    ae_q = db.query(AlertEvent).filter(AlertEvent.fired_at >= since)
    if src_ip:
        ae_q = ae_q.filter(AlertEvent.detail.contains(src_ip))
    if hostname:
        ae_q = ae_q.filter(AlertEvent.detail.contains(hostname))
    alert_events = ae_q.order_by(AlertEvent.fired_at.desc()).limit(10).all()

    return {
        "detection_matches": [
            {
                "id": m.id,
                "rule_name": m.rule_name,
                "severity": m.severity,
                "matched_at": m.matched_at.isoformat() if m.matched_at else None,
                "mitre_techniques": json.loads(m.mitre_techniques_json or "[]"),
                "matched_fields": json.loads(m.matched_fields_json or "{}"),
            }
            for m in matches
        ],
        "alert_events": [
            {
                "id": e.id,
                "rule_name": e.rule_name,
                "fired_at": e.fired_at.isoformat() if e.fired_at else None,
                "detail": (e.detail or "")[:300],
                "acknowledged": e.acknowledged,
            }
            for e in alert_events
        ],
    }


# ── Investigation runner ──────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a SOC analyst AI investigating a security alert.
Use the provided tools to gather evidence. Be thorough but efficient — use at most 10 tool calls.
Conclude with a verdict: true_positive, false_positive, or inconclusive.
Provide a concise investigation summary (3-5 sentences) covering: what happened, affected entities, \
confidence level, and recommended action.
"""


def _get_anthropic_client():
    """Lazily initialize the Anthropic client."""
    import anthropic
    from database import get_service_setting
    from config import settings
    api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
    if not api_key:
        raise RuntimeError("Anthropic API key not configured. Add it in Settings > AI Configuration.")
    return anthropic.AsyncAnthropic(api_key=api_key), api_key


def _extract_verdict(text: str) -> Optional[str]:
    """Extract verdict keyword from AI response text."""
    text_lower = text.lower()
    if "true_positive" in text_lower:
        return "true_positive"
    if "false_positive" in text_lower:
        return "false_positive"
    if "inconclusive" in text_lower:
        return "inconclusive"
    return None


async def run_investigation(investigation_id: int, context: dict, db) -> None:
    """
    Run a full ReAct investigation loop for the given investigation record.
    Uses its own DB session — must NOT use the caller's request-scoped session.
    """
    from database import Investigation, InvestigationStep
    from database import get_service_setting

    inv = db.query(Investigation).filter_by(id=investigation_id).first()
    if not inv:
        logger.error("Investigation %d not found", investigation_id)
        return

    try:
        client, _ = _get_anthropic_client()
    except RuntimeError as exc:
        inv.status = "failed"
        inv.summary = str(exc)
        inv.completed_at = datetime.now(timezone.utc)
        db.commit()
        return

    # Select model
    model = get_service_setting("claude_model") or "claude-haiku-4-5-20251001"
    # Fallback to known-good model if haiku variant isn't available
    fallback_model = "claude-sonnet-4-6"

    # Build user prompt from context
    context_lines = [f"Trigger type: {inv.trigger_type}"]
    if inv.trigger_id:
        context_lines.append(f"Trigger ID: {inv.trigger_id}")
    context_lines.append(f"Title: {inv.title}")
    context_lines.append(f"Severity: {inv.severity or 'unknown'}")
    for k, v in (context or {}).items():
        context_lines.append(f"{k}: {v}")
    user_prompt = "\n".join(context_lines)

    messages = [{"role": "user", "content": user_prompt}]
    step_number = 0
    summary_text = ""
    verdict = None
    final_model = model

    try:
        for _iteration in range(12):  # max 12 iterations to allow up to 10 tool calls
            try:
                response = await client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=_SYSTEM_PROMPT,
                    messages=messages,
                    tools=INVESTIGATOR_TOOLS,
                    timeout=120.0,
                )
            except Exception as model_exc:
                # If the haiku model isn't found, try fallback
                if "not found" in str(model_exc).lower() or "404" in str(model_exc):
                    logger.warning("Model %s not found, falling back to %s", model, fallback_model)
                    model = fallback_model
                    final_model = model
                    response = await client.messages.create(
                        model=model,
                        max_tokens=4096,
                        system=_SYSTEM_PROMPT,
                        messages=messages,
                        tools=INVESTIGATOR_TOOLS,
                        timeout=120.0,
                    )
                else:
                    raise

            # Check for final text response
            if response.stop_reason == "end_turn":
                text_blocks = [b.text for b in response.content if hasattr(b, "text")]
                summary_text = " ".join(text_blocks).strip()
                verdict = _extract_verdict(summary_text)
                break

            if response.stop_reason != "tool_use":
                # Unexpected stop reason — extract any text
                text_blocks = [b.text for b in response.content if hasattr(b, "text")]
                summary_text = " ".join(text_blocks).strip()
                verdict = _extract_verdict(summary_text)
                break

            if step_number >= 10:
                # Reached tool call limit — send a final prompt
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": "You have used the maximum number of tool calls. Please provide your final verdict and summary now.",
                })
                continue

            # Process tool calls
            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                step_number += 1
                t_start = time.monotonic()
                tool_output = await _execute_tool(block.name, block.input, db)
                duration_ms = int((time.monotonic() - t_start) * 1000)

                # Extract reasoning from preceding text blocks
                reasoning_blocks = [b.text for b in response.content if hasattr(b, "text") and b.text]
                reasoning = " ".join(reasoning_blocks).strip()[:1000] if reasoning_blocks else None

                # Persist step immediately
                step = InvestigationStep(
                    investigation_id=investigation_id,
                    step_number=step_number,
                    tool_name=block.name,
                    tool_input_json=json.dumps(block.input),
                    tool_output_json=json.dumps(tool_output),
                    reasoning=reasoning,
                    duration_ms=duration_ms,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(step)
                db.commit()
                logger.info("Investigation %d step %d: tool=%s duration=%dms",
                            investigation_id, step_number, block.name, duration_ms)

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(tool_output),
                })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        # Update investigation record
        inv.status = "complete"
        inv.summary = summary_text or "Investigation completed."
        inv.verdict = verdict
        inv.completed_at = datetime.now(timezone.utc)
        inv.model_used = final_model
        db.commit()
        logger.info("Investigation %d completed: verdict=%s steps=%d",
                    investigation_id, verdict, step_number)

    except Exception as exc:
        logger.error("Investigation %d failed: %s", investigation_id, exc, exc_info=True)
        try:
            inv.status = "failed"
            inv.summary = str(exc)[:1000]
            inv.completed_at = datetime.now(timezone.utc)
            inv.model_used = final_model
            db.commit()
        except Exception:
            pass


# ── Auto-trigger ──────────────────────────────────────────────────────────────

async def maybe_auto_investigate(
    trigger_type: str,
    trigger_id: int,
    title: str,
    severity: str,
    context: dict,
    db,
) -> Optional[int]:
    """
    Auto-trigger an investigation for high/critical severity events if enabled.
    Returns the investigation_id if started, else None.
    """
    if severity not in ("critical", "high"):
        return None

    from database import get_service_setting, Investigation, SessionLocal

    auto = get_service_setting("auto_investigate", db=db)
    if auto == "0":
        return None

    # Create investigation record
    inv = Investigation(
        trigger_type=trigger_type,
        trigger_id=trigger_id,
        title=title[:256],
        status="running",
        severity=severity,
        created_at=datetime.now(timezone.utc),
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    inv_id = inv.id

    logger.info("Auto-investigation %d started for %s (severity=%s)", inv_id, title, severity)

    # Fire-and-forget background task with its own DB session
    async def _bg_task():
        bg_db = SessionLocal()
        try:
            await run_investigation(inv_id, context, bg_db)
        except Exception as exc:
            logger.error("Background investigation %d error: %s", inv_id, exc)
        finally:
            bg_db.close()

    asyncio.create_task(_bg_task())
    return inv_id


# ── Background watcher ────────────────────────────────────────────────────────

async def run_investigation_watcher():
    """
    Background loop running every 30 seconds.
    Picks up Investigation records stuck in status='running' (e.g. from a restart)
    and re-runs them, and picks up any 'pending' records.
    """
    logger.info("Investigation watcher started.")
    while True:
        try:
            from database import Investigation, SessionLocal
            db = SessionLocal()
            try:
                # Find investigations that are pending or stuck in running state
                # (running for more than 5 minutes = likely stuck from a restart)
                stuck_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                stuck = (
                    db.query(Investigation)
                    .filter(
                        (Investigation.status == "pending") |
                        (
                            (Investigation.status == "running") &
                            (Investigation.created_at <= stuck_cutoff)
                        )
                    )
                    .limit(5)
                    .all()
                )
                for inv in stuck:
                    inv_id = inv.id
                    context = {}
                    if inv.summary:
                        context["initial_context"] = inv.summary
                    logger.info("Investigation watcher: re-running investigation %d (status=%s)", inv_id, inv.status)
                    inv.status = "running"
                    db.commit()

                    async def _watcher_bg(iid=inv_id, ctx=context):
                        bg_db = SessionLocal()
                        try:
                            await run_investigation(iid, ctx, bg_db)
                        except Exception as exc:
                            logger.error("Watcher investigation %d error: %s", iid, exc)
                        finally:
                            bg_db.close()

                    asyncio.create_task(_watcher_bg())
            finally:
                db.close()
        except asyncio.CancelledError:
            logger.info("Investigation watcher cancelled.")
            return
        except Exception as exc:
            logger.error("Investigation watcher error: %s", exc)

        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            return
