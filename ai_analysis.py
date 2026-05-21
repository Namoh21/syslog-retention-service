"""
Claude AI analysis of syslog data.
Provides security recommendations based on ingested log entries.
"""
import logging
from datetime import datetime, timezone
from typing import Any

import anthropic

from config import settings
from database import FACILITY_NAMES, SEVERITY_NAMES, SyslogEntry

logger = logging.getLogger("ai_analysis")

_ANALYSIS_TASK = """\
You are a network security analyst reviewing syslog data from a Unifi Dream Machine (UDM) \
and associated network devices. Your job is to:

1. Identify security threats, anomalies, and suspicious patterns in the log data.
2. Highlight configuration weaknesses or misconfigurations.
3. Surface high-severity events (Emergency, Alert, Critical, Error) for immediate attention.
4. Provide concrete, actionable recommendations to improve network security.
5. When historical context is provided, avoid repeating recommendations already marked as
   IMPLEMENTED or WORKING. Reference prior findings when relevant. Note any regressions.\
"""

_JSON_SCHEMA = """\
{
  "summary": "<2-3 sentence executive summary>",
  "threat_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
  "findings": [
    {
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "title": "<short title>",
      "detail": "<what was observed and why it matters>",
      "recommendation": "<specific action to take>"
    }
  ],
  "immediate_actions": ["<urgent action 1>", "<urgent action 2>"],
  "long_term_recommendations": ["<strategic recommendation 1>"]
}\
"""

# Anthropic — conversational system prompt, model follows instructions reliably
_SYSTEM_PROMPT = f"""\
{_ANALYSIS_TASK}

Respond ONLY with a valid JSON object matching this exact schema — no prose, no markdown, \
no code fences, no explanation before or after the JSON:
{_JSON_SCHEMA}

Be specific and reference actual log entries, IPs, and rule names where relevant.\
"""

# Local LLM — more forceful; many smaller models need explicit repetition
_SYSTEM_PROMPT_LOCAL = f"""\
You are a JSON-only network security analyst. You MUST respond with ONLY a valid JSON object. \
Do NOT include any text, explanation, markdown, or code fences outside the JSON object. \
Your entire response must start with {{ and end with }}.

{_ANALYSIS_TASK}

Output schema (follow exactly):
{_JSON_SCHEMA}

IMPORTANT: Output JSON only. Start your response with {{ immediately.\
"""


_MAX_MSG_CHARS = 160        # keep each log line short to stay under token limits
_MAX_TOTAL_CHARS = 80_000   # Anthropic: hard cap (~20k tokens)
_MAX_TOTAL_CHARS_LOCAL = 400_000  # Local LLM: much higher — no token billing concern


def _format_entries(entries: list[SyslogEntry], *, local_llm: bool = False) -> str:
    max_chars = _MAX_TOTAL_CHARS_LOCAL if local_llm else _MAX_TOTAL_CHARS
    lines = []
    total = 0
    for e in entries:
        sev = SEVERITY_NAMES[e.severity] if e.severity is not None and e.severity < 8 else str(e.severity)
        ts = e.received_at.strftime("%Y-%m-%d %H:%M:%S") if e.received_at else "?"
        msg = (e.message or "")[:_MAX_MSG_CHARS]
        line = (f"[{ts}][{sev}][{e.source_ip or '?'}] {e.app_name or ''}: {msg}")
        total += len(line)
        if total > max_chars:
            lines.append(f"... truncated at {len(lines)} entries (char limit reached)")
            break
        lines.append(line)
    return "\n".join(lines)


def _build_history_context(db) -> str:
    """
    Build an analyst-memory block from stored analyses and recommendation outcomes.
    Included in every new analysis so Claude knows what's been addressed.
    """
    import json as _json
    from database import AIAnalysis, AIRecommendation, AINetworkContext, AIContextEntry

    lines = ["=== ANALYST MEMORY ===\n"]

    # User's network notes (legacy free-form notes)
    ctx = db.query(AINetworkContext).filter_by(id=1).first()
    if ctx and ctx.content and ctx.content.strip():
        lines.append("NETWORK CONTEXT (provided by the analyst):")
        lines.append(ctx.content.strip())
        lines.append("")

    # Structured knowledge base entries
    kb_entries = (
        db.query(AIContextEntry)
        .filter(AIContextEntry.active == 1)
        .order_by(AIContextEntry.category, AIContextEntry.id)
        .all()
    )
    if kb_entries:
        # Group by category
        from collections import defaultdict
        by_cat: dict[str, list] = defaultdict(list)
        for e in kb_entries:
            by_cat[e.category].append(e)
        lines.append("KNOWLEDGE BASE (analyst-curated context for this network):")
        for cat, entries in by_cat.items():
            lines.append(f"\n[{cat.upper().replace('_', ' ')}]")
            for e in entries:
                lines.append(f"  {e.title}:")
                for ln in e.content.strip().splitlines():
                    lines.append(f"    {ln}")
        lines.append("")

    # Recent analyses — last 5
    past = (
        db.query(AIAnalysis)
        .order_by(AIAnalysis.analyzed_at.desc())
        .limit(5)
        .all()
    )
    if past:
        lines.append("PREVIOUS ANALYSES AND RECOMMENDATION STATUS:")
        for a in reversed(past):  # oldest first
            ts = a.analyzed_at.strftime("%Y-%m-%d") if a.analyzed_at else "?"
            lines.append(f"\n[{ts}] Threat: {a.threat_level or '?'} | {a.summary or ''}")
            recs = (
                db.query(AIRecommendation)
                .filter_by(analysis_id=a.id)
                .all()
            )
            non_open = [r for r in recs if r.status != "open"]
            open_recs = [r for r in recs if r.status == "open"]
            for r in non_open:
                note = f" — {r.user_notes}" if r.user_notes else ""
                lines.append(f"  [{r.status.upper()}] {r.title}{note}")
            if open_recs:
                lines.append(f"  Still open: {', '.join(r.title or '?' for r in open_recs[:5])}")

    lines.append("\n=== END ANALYST MEMORY ===\n")
    return "\n".join(lines) if len(lines) > 3 else ""


def _build_netflow_context(db, hours: float) -> str:
    """Summarise recent NetFlow data to include in the AI prompt."""
    try:
        from database import NetFlowRecord, SessionLocal
        from sqlalchemy import func as sqlfunc
        own = db is None
        if own:
            db = SessionLocal()
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        try:
            total = db.query(sqlfunc.count(NetFlowRecord.id)).filter(NetFlowRecord.received_at >= since).scalar() or 0
            if total == 0:
                return ""
            total_bytes = db.query(sqlfunc.sum(NetFlowRecord.bytes)).filter(NetFlowRecord.received_at >= since).scalar() or 0
            top_talkers = (
                db.query(NetFlowRecord.src_ip, sqlfunc.sum(NetFlowRecord.bytes).label("b"))
                .filter(NetFlowRecord.received_at >= since)
                .group_by(NetFlowRecord.src_ip).order_by(sqlfunc.sum(NetFlowRecord.bytes).desc()).limit(8).all()
            )
            top_ports = (
                db.query(NetFlowRecord.dst_port, NetFlowRecord.proto_name, sqlfunc.count(NetFlowRecord.id).label("c"))
                .filter(NetFlowRecord.received_at >= since, NetFlowRecord.dst_port.isnot(None))
                .group_by(NetFlowRecord.dst_port, NetFlowRecord.proto_name)
                .order_by(sqlfunc.count(NetFlowRecord.id).desc()).limit(8).all()
            )
            lines = [f"=== NETFLOW SUMMARY (last {hours}h) ==="]
            lines.append(f"Total flows: {total:,}  |  Total bytes: {total_bytes:,}")
            if top_talkers:
                lines.append("Top bandwidth sources:")
                for ip, b in top_talkers:
                    lines.append(f"  {ip}: {b:,} bytes")
            if top_ports:
                lines.append("Top destination ports:")
                for port, proto, c in top_ports:
                    lines.append(f"  {port}/{proto}: {c:,} flows")
            lines.append("=== END NETFLOW SUMMARY ===")
            return "\n".join(lines)
        finally:
            if own:
                db.close()
    except Exception as exc:
        logger.debug("NetFlow context build failed: %s", exc)
        return ""


def _save_analysis(db, result: dict, focus: str, hours: int) -> "AIAnalysis | None":
    """Persist an analysis result and its individual findings."""
    import json as _json
    from database import AIAnalysis, AIRecommendation
    analysis = result.get("analysis", {})
    if not isinstance(analysis, dict) or analysis.get("raw"):
        return None
    try:
        record = AIAnalysis(
            focus=focus[:256],
            hours_covered=hours,
            log_count=result.get("log_count", 0),
            threat_level=analysis.get("threat_level"),
            summary=analysis.get("summary"),
            immediate_actions_json=_json.dumps(analysis.get("immediate_actions", [])),
            findings_json=_json.dumps(analysis.get("findings", [])),
        )
        db.add(record)
        db.flush()  # get record.id

        for f in analysis.get("findings", []):
            if not isinstance(f, dict):
                continue
            db.add(AIRecommendation(
                analysis_id=record.id,
                title=str(f.get("title", ""))[:256],
                severity=str(f.get("severity", "INFO"))[:16],
                detail=str(f.get("detail", "")),
                recommendation=str(f.get("recommendation", "")),
                status="open",
            ))
        db.commit()
        return record
    except Exception as exc:
        logger.warning("Could not save analysis to DB: %s", exc)
        db.rollback()
        return None


async def _call_anthropic(
    api_key: str,
    model: str,
    user_message: str,
) -> str:
    client = anthropic.AsyncAnthropic(api_key=api_key)
    try:
        response = await client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
            timeout=60.0,
        )
        return response.content[0].text
    except anthropic.RateLimitError:
        raise
    except anthropic.APIError:
        raise


async def _call_local_llm(
    base_url: str,
    model: str,
    user_message: str,
) -> str:
    import httpx as _httpx

    # For small local models, showing the schema in the system prompt causes them
    # to echo the schema template with empty values. Instead:
    # - system prompt is short and task-focused (no schema)
    # - the schema + a filled example appear in the user message
    # - no response_format constraint (causes minimal-JSON echoing in small models)
    system = (
        "You are a network security analyst. "
        "Read the log data and write a thorough security analysis. "
        "Your entire response must be a single JSON object — no other text."
    )

    example = '''{
  "summary": "Two external IPs made repeated connection attempts to SSH and RDP ports over the past hour, suggesting an active brute-force campaign. Several firewall blocks logged from 203.0.113.45 targeting port 22.",
  "threat_level": "HIGH",
  "findings": [
    {
      "severity": "HIGH",
      "title": "SSH brute-force from 203.0.113.45",
      "detail": "47 blocked connection attempts to port 22 from 203.0.113.45 between 03:12 and 03:58 UTC. Pattern matches automated credential stuffing.",
      "recommendation": "Add 203.0.113.45 to the UDM block list and enable geo-IP blocking for regions with no legitimate users."
    }
  ],
  "immediate_actions": ["Block 203.0.113.45 at the perimeter firewall immediately."],
  "long_term_recommendations": ["Enable fail2ban or equivalent on all SSH-exposed hosts."]
}'''

    user = (
        f"{user_message}\n\n"
        f"Write your analysis as a JSON object in exactly this format "
        f"(fill in real content from the logs above — do NOT copy the example values):\n"
        f"{example}"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens": 4096,
        "temperature": 0.3,
        "stream": False,
    }
    async with _httpx.AsyncClient(timeout=600.0) as client:
        r = await client.post(f"{base_url}/v1/chat/completions", json=payload)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def _extract_json(text: str) -> dict:
    """
    Robustly extract a JSON object from LLM output, then normalise field names.
    Handles: valid JSON, markdown code fences, JSON buried in prose,
    trailing commas. Falls back to {"summary": text, "raw": True}.
    """
    import json as _json
    import re as _re

    def _try_parse(s: str):
        try:
            return _json.loads(s)
        except _json.JSONDecodeError:
            # Fix trailing commas before ] or }
            fixed = _re.sub(r",\s*([}\]])", r"\1", s)
            try:
                return _json.loads(fixed)
            except _json.JSONDecodeError:
                return None

    # 1. Direct parse
    obj = _try_parse(text)
    if obj is None:
        # 2. Strip markdown code fences
        fence = _re.search(r"```(?:json)?\s*([\s\S]*?)```", text.strip())
        if fence:
            obj = _try_parse(fence.group(1).strip())

    if obj is None:
        # 3. Find outermost { ... } block
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            obj = _try_parse(text[start: end + 1])

    if not isinstance(obj, dict):
        logger.warning("Could not extract JSON from LLM response (%d chars). Returning raw.", len(text))
        return {"summary": text, "raw": True}

    logger.debug("LLM JSON keys returned: %s", list(obj.keys()))
    return _normalise(obj)


def _normalise(obj: dict) -> dict:
    """
    Map common alternative field names used by local LLMs to the canonical schema.
    Also normalises nested findings fields.
    """
    # ── Top-level field aliases ────────────────────────────────────────────────
    _SUMMARY_KEYS = [
        "summary", "executive_summary", "overview", "analysis_summary",
        "description", "analysis", "result", "report", "conclusion",
    ]
    _THREAT_KEYS = [
        "threat_level", "risk_level", "severity", "threat_assessment",
        "overall_threat", "risk", "overall_risk", "threat", "level",
        "overall_severity", "threat_rating", "risk_rating",
    ]
    _FINDINGS_KEYS = [
        "findings", "security_findings", "issues", "vulnerabilities",
        "alerts", "observations", "security_issues", "threats",
        "security_alerts", "events", "results",
    ]
    _IMMEDIATE_KEYS = [
        "immediate_actions", "immediate_recommendations", "urgent_actions",
        "action_items", "actions", "urgent_recommendations", "critical_actions",
        "priority_actions", "next_steps",
    ]
    _LONGTERM_KEYS = [
        "long_term_recommendations", "recommendations", "long_term",
        "strategic_recommendations", "long_term_actions", "future_recommendations",
        "additional_recommendations", "ongoing_recommendations",
    ]

    def _pick(keys):
        for k in keys:
            if obj.get(k):
                return obj[k]
        return None

    # ── Threat level normalisation ─────────────────────────────────────────────
    raw_tl = _pick(_THREAT_KEYS) or ""
    tl_map = {
        "critical": "CRITICAL", "crit": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM", "moderate": "MEDIUM", "med": "MEDIUM",
        "low": "LOW",
        "info": "LOW", "informational": "LOW", "minimal": "LOW",
    }
    threat_level = tl_map.get(str(raw_tl).lower().strip(), str(raw_tl).upper().strip() or "UNKNOWN")
    if threat_level not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        threat_level = "UNKNOWN"

    # ── Findings normalisation ─────────────────────────────────────────────────
    raw_findings = _pick(_FINDINGS_KEYS) or []
    if isinstance(raw_findings, dict):
        raw_findings = list(raw_findings.values())
    findings = []
    for f in (raw_findings if isinstance(raw_findings, list) else []):
        if not isinstance(f, dict):
            continue
        # Severity aliases
        sev_raw = (f.get("severity") or f.get("level") or f.get("risk") or f.get("priority") or "INFO")
        sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                   "moderate": "MEDIUM", "low": "LOW", "info": "INFO",
                   "informational": "INFO", "minimal": "LOW"}
        severity = sev_map.get(str(sev_raw).lower().strip(), str(sev_raw).upper())
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            severity = "INFO"

        findings.append({
            "severity":       severity,
            "title":          (f.get("title") or f.get("name") or f.get("issue") or f.get("finding") or "Finding"),
            "detail":         (f.get("detail") or f.get("description") or f.get("details") or f.get("explanation") or ""),
            "recommendation": (f.get("recommendation") or f.get("remediation") or f.get("action") or f.get("fix") or f.get("mitigation") or ""),
        })

    # ── List fields ────────────────────────────────────────────────────────────
    def _to_list(v):
        if isinstance(v, list):
            return [str(i) for i in v if i]
        if isinstance(v, str) and v:
            return [v]
        return []

    return {
        "summary":                  (_pick(_SUMMARY_KEYS) or ""),
        "threat_level":             threat_level,
        "findings":                 findings,
        "immediate_actions":        _to_list(_pick(_IMMEDIATE_KEYS)),
        "long_term_recommendations": _to_list(_pick(_LONGTERM_KEYS)),
    }


async def analyze_logs(
    entries: list[SyslogEntry],
    *,
    focus: str = "security",
    hours: int = 24,
    db=None,          # optional session — used to load/save history
) -> dict[str, Any]:
    import json as _json
    from database import get_service_setting, SessionLocal

    ai_provider = get_service_setting("ai_provider") or "anthropic"

    own_session = db is None
    if own_session:
        db = SessionLocal()

    try:
        history_block = _build_history_context(db)
    except Exception:
        history_block = ""
    finally:
        if own_session:
            db.close()
            db = None

    log_text = _format_entries(entries, local_llm=(ai_provider == "local"))

    # Append NetFlow summary if data exists
    netflow_block = _build_netflow_context(db if not own_session else None, hours)
    if netflow_block:
        log_text = netflow_block + "\n\n" + log_text
    focus_safe = focus[:200] if focus else "security threats and anomalies"
    user_message = (
        f"{history_block}"
        f"Please analyze the following {len(entries)} syslog entries from the last {hours} hours. "
        f"Focus on: {focus_safe}.\n\n"
        f"=== LOG DATA ===\n{log_text}\n=== END LOG DATA ==="
    )

    if ai_provider == "local":
        base_url = get_service_setting("ai_local_url") or ""
        model = get_service_setting("ai_local_model") or "llama3.2"
        if not base_url:
            return {
                "error": "Local LLM URL not configured. Set it in Settings > AI Configuration.",
                "log_count": len(entries),
            }
        try:
            raw_text = await _call_local_llm(base_url, model, user_message)
        except Exception as exc:
            logger.error("Local LLM error: %s", exc)
            return {"error": f"Local LLM error: {exc}", "log_count": len(entries)}
    else:
        api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
        if not api_key:
            return {
                "error": "Anthropic API key not configured. Add it in Settings > AI Configuration.",
                "log_count": len(entries),
            }
        model = get_service_setting("claude_model") or settings.claude_model
        try:
            raw_text = await _call_anthropic(api_key, model, user_message)
        except anthropic.RateLimitError:
            logger.warning("Anthropic rate limit hit")
            return {
                "error": (
                    "Rate limit reached (30,000 input tokens/min). "
                    "Try a shorter time window or reduce 'Max logs per AI analysis' "
                    "in Settings → Service Configuration. "
                    "Wait 60 seconds and try again."
                ),
                "log_count": len(entries),
            }
        except anthropic.APIError as exc:
            logger.error("Anthropic API error: %s", exc)
            return {"error": f"Anthropic API error: {exc}", "log_count": len(entries)}

    logger.debug("Raw LLM response (first 500 chars): %s", raw_text[:500])
    analysis = _extract_json(raw_text)

    result = {
        "analysis": analysis,
        "log_count": len(entries),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "hours_covered": hours,
        "provider": ai_provider,
    }

    # Save to history (best-effort)
    try:
        save_db = SessionLocal()
        saved = _save_analysis(save_db, result, focus_safe, hours)
        if saved:
            result["analysis_id"] = saved.id
        save_db.close()
    except Exception as exc:
        logger.warning("Analysis save failed: %s", exc)

    return result
