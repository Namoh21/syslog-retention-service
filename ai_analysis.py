"""
AI-powered analysis of syslog data.
Supports Anthropic (Claude) and local OpenAI-compatible LLMs (Ollama, LM Studio).
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import anthropic

from config import settings
from database import SEVERITY_NAMES, SyslogEntry

logger = logging.getLogger("ai_analysis")

# ── Prompt constants ──────────────────────────────────────────────────────────

_ANALYSIS_TASK = """\
You are a network security analyst reviewing syslog data from a Unifi Dream Machine (UDM) \
and associated network devices. Your job is to:
1. Identify security threats, anomalies, and suspicious patterns.
2. Highlight configuration weaknesses or misconfigurations.
3. Surface high-severity events (Emergency, Alert, Critical, Error) for immediate attention.
4. Provide concrete, actionable recommendations to improve network security.
5. When historical context is provided, avoid repeating items already marked IMPLEMENTED or \
WORKING. Reference prior findings when relevant and note any regressions.\
"""

# Canonical JSON schema shown to Anthropic (reliable instruction-follower)
_SYSTEM_PROMPT = f"""\
{_ANALYSIS_TASK}

Respond ONLY with a valid JSON object — no prose, no markdown fences, no explanation outside \
the JSON. Use exactly these keys:
{{
  "summary": "<2-3 sentence executive summary>",
  "threat_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
  "findings": [
    {{
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
      "title": "<short descriptive title>",
      "detail": "<what was observed and why it matters>",
      "recommendation": "<specific action to take>"
    }}
  ],
  "immediate_actions": ["<urgent action 1>"],
  "long_term_recommendations": ["<strategic recommendation 1>"]
}}

Be specific — reference actual IPs, timestamps, rule names, and port numbers from the logs.\
"""

# Local LLM prompt — short system, example-driven user message (avoids schema-echo in small models)
_LOCAL_SYSTEM = (
    "You are a network security analyst. "
    "Analyze the provided log data and respond with ONLY a JSON object. "
    "No other text, no markdown, no explanation — just the JSON."
)

_LOCAL_EXAMPLE = """{
  "summary": "Repeated SSH brute-force attempts detected from 203.0.113.45. Several high-severity firewall blocks logged in the past hour.",
  "threat_level": "HIGH",
  "findings": [
    {
      "severity": "HIGH",
      "title": "SSH brute-force from 203.0.113.45",
      "detail": "47 blocked connection attempts to port 22 from 203.0.113.45 between 03:12 and 03:58 UTC. Pattern matches automated credential stuffing.",
      "recommendation": "Block 203.0.113.45 in the UDM firewall and enable geo-IP filtering for regions with no legitimate users."
    }
  ],
  "immediate_actions": ["Block 203.0.113.45 at the perimeter firewall immediately."],
  "long_term_recommendations": ["Enable fail2ban or equivalent on all internet-exposed services."]
}"""

# ── Log formatting ────────────────────────────────────────────────────────────

_MAX_MSG_CHARS = 160
_MAX_TOTAL_CHARS = 80_000          # Anthropic (~20k tokens)
_MAX_TOTAL_CHARS_LOCAL = 400_000   # Local — no billing concern


def _format_entries(entries: list[SyslogEntry], *, local_llm: bool = False) -> str:
    max_chars = _MAX_TOTAL_CHARS_LOCAL if local_llm else _MAX_TOTAL_CHARS
    lines: list[str] = []
    total = 0
    for e in entries:
        sev = SEVERITY_NAMES[e.severity] if e.severity is not None and e.severity < 8 else str(e.severity)
        ts  = e.received_at.strftime("%Y-%m-%d %H:%M:%S") if e.received_at else "?"
        msg = (e.message or "")[:_MAX_MSG_CHARS]
        src = e.src_ip or e.source_ip or "?"
        dst = f"→{e.dst_ip}:{e.dst_port}" if e.dst_ip else ""
        act = f" [{e.action}]" if e.action else ""
        line = f"[{ts}][{sev}][{src}{dst}]{act} {e.app_name or ''}: {msg}"
        total += len(line)
        if total > max_chars:
            lines.append(f"... truncated at {len(lines)} entries (char limit reached)")
            break
        lines.append(line)
    return "\n".join(lines)


# ── Context builders ──────────────────────────────────────────────────────────

def _build_history_context(db) -> str:
    """Analyst memory: network notes, knowledge base, and past analyses."""
    from database import AIAnalysis, AIRecommendation, AINetworkContext, AIContextEntry
    from collections import defaultdict

    lines = ["=== ANALYST MEMORY ===\n"]

    ctx = db.query(AINetworkContext).filter_by(id=1).first()
    if ctx and ctx.content and ctx.content.strip():
        lines.append("NETWORK CONTEXT (provided by the analyst):")
        lines.append(ctx.content.strip())
        lines.append("")

    kb = (
        db.query(AIContextEntry)
        .filter(AIContextEntry.active == 1)
        .order_by(AIContextEntry.category, AIContextEntry.id)
        .all()
    )
    if kb:
        by_cat: dict[str, list] = defaultdict(list)
        for e in kb:
            by_cat[e.category].append(e)
        lines.append("KNOWLEDGE BASE:")
        for cat, entries in by_cat.items():
            lines.append(f"\n[{cat.upper().replace('_', ' ')}]")
            for e in entries:
                lines.append(f"  {e.title}:")
                for ln in e.content.strip().splitlines():
                    lines.append(f"    {ln}")
        lines.append("")

    past = (
        db.query(AIAnalysis)
        .order_by(AIAnalysis.analyzed_at.desc())
        .limit(5)
        .all()
    )
    if past:
        lines.append("PREVIOUS ANALYSES:")
        for a in reversed(past):
            ts = a.analyzed_at.strftime("%Y-%m-%d") if a.analyzed_at else "?"
            lines.append(f"\n[{ts}] Threat: {a.threat_level or '?'} | {a.summary or ''}")
            recs = db.query(AIRecommendation).filter_by(analysis_id=a.id).all()
            for r in [r for r in recs if r.status != "open"]:
                note = f" — {r.user_notes}" if r.user_notes else ""
                lines.append(f"  [{r.status.upper()}] {r.title}{note}")
            open_r = [r for r in recs if r.status == "open"]
            if open_r:
                lines.append(f"  Still open: {', '.join(r.title or '?' for r in open_r[:5])}")

    lines.append("\n=== END ANALYST MEMORY ===\n")
    return "\n".join(lines) if len(lines) > 3 else ""


def _build_netflow_context(db, hours: float) -> str:
    """Summarise recent NetFlow data to prepend to the log analysis."""
    try:
        from database import NetFlowRecord, SessionLocal
        from sqlalchemy import func as sqlfunc
        own = db is None
        if own:
            db = SessionLocal()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            total = db.query(sqlfunc.count(NetFlowRecord.id)).filter(NetFlowRecord.received_at >= since).scalar() or 0
            if not total:
                return ""
            total_bytes = db.query(sqlfunc.sum(NetFlowRecord.bytes)).filter(NetFlowRecord.received_at >= since).scalar() or 0
            top_talkers = (
                db.query(NetFlowRecord.src_ip, sqlfunc.sum(NetFlowRecord.bytes).label("b"))
                .filter(NetFlowRecord.received_at >= since)
                .group_by(NetFlowRecord.src_ip)
                .order_by(sqlfunc.sum(NetFlowRecord.bytes).desc())
                .limit(8).all()
            )
            top_ports = (
                db.query(NetFlowRecord.dst_port, NetFlowRecord.proto_name, sqlfunc.count(NetFlowRecord.id).label("c"))
                .filter(NetFlowRecord.received_at >= since, NetFlowRecord.dst_port.isnot(None))
                .group_by(NetFlowRecord.dst_port, NetFlowRecord.proto_name)
                .order_by(sqlfunc.count(NetFlowRecord.id).desc())
                .limit(8).all()
            )
            lines = [f"=== NETFLOW SUMMARY (last {hours}h) ===",
                     f"Total flows: {total:,}  |  Total bytes: {total_bytes:,}"]
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
        logger.warning("NetFlow context build failed: %s", exc)
        return ""


# ── Persistence ───────────────────────────────────────────────────────────────

def _save_analysis(db, result: dict, focus: str, hours: float) -> "AIAnalysis | None":
    import json as _json
    from database import AIAnalysis, AIRecommendation
    analysis = result.get("analysis", {})
    if not isinstance(analysis, dict) or analysis.get("raw"):
        return None
    try:
        record = AIAnalysis(
            focus=focus[:256],
            hours_covered=int(hours),
            log_count=result.get("log_count", 0),
            threat_level=analysis.get("threat_level"),
            summary=analysis.get("summary"),
            immediate_actions_json=_json.dumps(analysis.get("immediate_actions", [])),
            findings_json=_json.dumps(analysis.get("findings", [])),
        )
        db.add(record)
        db.flush()
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
        logger.warning("Analysis save failed: %s", exc)
        db.rollback()
        return None


# ── LLM callers ───────────────────────────────────────────────────────────────

async def _call_anthropic(api_key: str, model: str, user_message: str) -> str:
    client = anthropic.AsyncAnthropic(api_key=api_key)
    logger.info("Calling Anthropic API — model=%s", model)
    try:
        response = await client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
            timeout=120.0,   # 2 min — large log sets need it
        )
        text = response.content[0].text
        logger.info("Anthropic response received — %d chars, stop_reason=%s",
                    len(text), response.stop_reason)
        return text
    except anthropic.RateLimitError:
        raise
    except anthropic.AuthenticationError as exc:
        logger.error("Anthropic auth failed — check API key: %s", exc)
        raise
    except anthropic.NotFoundError as exc:
        logger.error("Anthropic model not found (%s) — update model in Service Settings: %s", model, exc)
        raise
    except anthropic.APIError as exc:
        logger.error("Anthropic API error: %s", exc)
        raise


async def _call_local_llm(base_url: str, model: str, user_message: str) -> str:
    import httpx as _httpx
    # Small models echo an abstract schema with empty values when given one.
    # Instead: short system prompt + concrete filled example in the user message.
    user = (
        f"{user_message}\n\n"
        f"Analyze the log data above and respond with a JSON object in this exact format "
        f"(use real content from the logs — do NOT copy the example values):\n"
        f"{_LOCAL_EXAMPLE}"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _LOCAL_SYSTEM},
            {"role": "user",   "content": user},
        ],
        "max_tokens": 4096,
        "temperature": 0.3,
        "stream": False,
    }
    logger.info("Calling local LLM — model=%s url=%s", model, base_url)
    async with _httpx.AsyncClient(timeout=600.0) as client:
        r = await client.post(f"{base_url}/v1/chat/completions", json=payload)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
        logger.info("Local LLM response received — %d chars", len(text))
        return text


# ── JSON extraction & normalisation ──────────────────────────────────────────

def _extract_json(text: str) -> dict:
    """
    Extract and normalise a JSON object from raw LLM output.
    Handles: plain JSON, markdown fences, JSON buried in prose, trailing commas.
    """
    import json as _json, re as _re

    def _try(s: str):
        try:
            return _json.loads(s)
        except _json.JSONDecodeError:
            fixed = _re.sub(r",\s*([}\]])", r"\1", s)
            try:
                return _json.loads(fixed)
            except _json.JSONDecodeError:
                return None

    obj = _try(text)

    if obj is None:
        fence = _re.search(r"```(?:json)?\s*([\s\S]*?)```", text.strip())
        if fence:
            obj = _try(fence.group(1).strip())

    if obj is None:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            obj = _try(text[start: end + 1])

    if not isinstance(obj, dict):
        logger.warning("Could not extract JSON from LLM response (%d chars)", len(text))
        return {"summary": text, "raw": True}

    logger.info("LLM JSON keys: %s", list(obj.keys()))

    # Unwrap single-key wrapper: {"analysis": {...}} → inner dict
    _SCHEMA_KEYS = {"summary", "threat_level", "findings", "immediate_actions",
                    "long_term_recommendations", "executive_summary", "risk_level",
                    "security_findings", "issues", "vulnerabilities", "recommendations"}
    if len(obj) == 1:
        inner = next(iter(obj.values()))
        if isinstance(inner, dict):
            logger.info("Unwrapping single-key wrapper, inner keys: %s", list(inner.keys()))
            obj = inner
    else:
        for k, v in obj.items():
            if isinstance(v, dict) and _SCHEMA_KEYS & set(v.keys()):
                logger.info("Unwrapping schema-like key '%s', inner keys: %s", k, list(v.keys()))
                obj = v
                break

    return _normalise(obj)


def _normalise(obj: dict) -> dict:
    """Map common LLM field name variants to the canonical schema."""

    _SUMMARY_KEYS   = ["summary", "executive_summary", "overview", "analysis_summary",
                       "description", "report", "conclusion", "narrative", "assessment"]
    _THREAT_KEYS    = ["threat_level", "risk_level", "severity", "threat_assessment",
                       "overall_threat", "risk", "overall_risk", "threat_rating",
                       "overall_severity", "risk_rating"]
    _FINDINGS_KEYS  = ["findings", "security_findings", "issues", "vulnerabilities",
                       "alerts", "observations", "security_issues", "threats",
                       "security_alerts", "events"]
    _IMMEDIATE_KEYS = ["immediate_actions", "immediate_recommendations", "urgent_actions",
                       "action_items", "actions", "urgent_recommendations", "next_steps",
                       "critical_actions", "priority_actions"]
    _LONGTERM_KEYS  = ["long_term_recommendations", "recommendations", "long_term",
                       "strategic_recommendations", "long_term_actions",
                       "additional_recommendations", "future_recommendations"]

    def _pick(keys):
        for k in keys:
            v = obj.get(k)
            if v:  # truthy — non-empty string, non-empty list, etc.
                return v
        return None

    # Threat level
    raw_tl = _pick(_THREAT_KEYS) or ""
    tl_map = {"critical": "CRITICAL", "crit": "CRITICAL", "high": "HIGH",
              "medium": "MEDIUM", "moderate": "MEDIUM", "med": "MEDIUM",
              "low": "LOW", "info": "LOW", "minimal": "LOW"}
    threat_level = tl_map.get(str(raw_tl).lower().strip(), str(raw_tl).upper().strip())
    if threat_level not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        threat_level = "UNKNOWN"

    # Findings
    raw_findings = _pick(_FINDINGS_KEYS) or []
    if isinstance(raw_findings, dict):
        raw_findings = list(raw_findings.values())
    findings = []
    for f in (raw_findings if isinstance(raw_findings, list) else []):
        if not isinstance(f, dict):
            continue
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

    def _to_list(v):
        if isinstance(v, list):
            return [str(i) for i in v if i]
        if isinstance(v, str) and v:
            return [v]
        return []

    result = {
        "summary":                   (_pick(_SUMMARY_KEYS) or ""),
        "threat_level":              threat_level,
        "findings":                  findings,
        "immediate_actions":         _to_list(_pick(_IMMEDIATE_KEYS)),
        "long_term_recommendations": _to_list(_pick(_LONGTERM_KEYS)),
    }
    logger.info("Normalised: threat=%s summary_len=%d findings=%d",
                result["threat_level"], len(result["summary"]), len(findings))
    return result


# ── Main entry point ──────────────────────────────────────────────────────────

async def analyze_logs(
    entries: list[SyslogEntry],
    *,
    focus: str = "security",
    hours: float = 24,
    db=None,
) -> dict[str, Any]:
    import json as _json
    from database import get_service_setting, SessionLocal

    ai_provider = get_service_setting("ai_provider") or "anthropic"
    is_local = ai_provider == "local"

    # Build history context (needs DB; close early if we opened our own)
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        history_block = _build_history_context(db)
    except Exception as exc:
        logger.warning("History context failed: %s", exc)
        history_block = ""
    finally:
        if own_session:
            db.close()
            db = None

    # Build log text
    log_text  = _format_entries(entries, local_llm=is_local)
    netflow   = _build_netflow_context(None, hours)   # opens its own session
    if netflow:
        log_text = netflow + "\n\n" + log_text

    focus_safe = (focus or "security threats and anomalies")[:200]
    user_message = (
        f"{history_block}"
        f"Analyze the following {len(entries)} syslog entries from the last {hours}h. "
        f"Focus on: {focus_safe}.\n\n"
        f"=== LOG DATA ===\n{log_text}\n=== END LOG DATA ==="
    )

    logger.info("Starting analysis — provider=%s entries=%d hours=%s focus=%s",
                ai_provider, len(entries), hours, focus_safe)

    # ── Call the appropriate LLM ───────────────────────────────────────────────
    if is_local:
        base_url = get_service_setting("ai_local_url") or ""
        model    = get_service_setting("ai_local_model") or "llama3.2"
        if not base_url:
            return {"error": "Local LLM URL not configured. Set it in Settings > AI Configuration.",
                    "log_count": len(entries)}
        try:
            raw_text = await _call_local_llm(base_url, model, user_message)
        except Exception as exc:
            logger.error("Local LLM error: %s", exc)
            return {"error": f"Local LLM error: {exc}", "log_count": len(entries)}
    else:
        api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
        if not api_key:
            return {"error": "Anthropic API key not configured. Add it in Settings > AI Configuration.",
                    "log_count": len(entries)}
        # Use the configured model; fall back to the config default if blank
        model = get_service_setting("claude_model") or settings.claude_model or "claude-sonnet-4-6"
        try:
            raw_text = await _call_anthropic(api_key, model, user_message)
        except anthropic.RateLimitError:
            logger.warning("Anthropic rate limit hit")
            return {"error": ("Rate limit reached. Try a shorter time window or reduce "
                              "'Max logs per AI analysis' in Settings → Service Configuration. "
                              "Wait 60 seconds and try again."),
                    "log_count": len(entries)}
        except anthropic.AuthenticationError:
            return {"error": "Anthropic API key is invalid or expired. Update it in Service Settings.",
                    "log_count": len(entries)}
        except anthropic.NotFoundError:
            return {"error": f"Model '{model}' not found. Update the Claude model in Service Settings.",
                    "log_count": len(entries)}
        except anthropic.APIError as exc:
            logger.error("Anthropic API error: %s", exc)
            return {"error": f"Anthropic API error: {exc}", "log_count": len(entries)}

    logger.info("Raw response (first 500 chars): %s", raw_text[:500])
    analysis = _extract_json(raw_text)

    result = {
        "analysis":      analysis,
        "log_count":     len(entries),
        "analyzed_at":   datetime.now(timezone.utc).isoformat(),
        "model":         model,
        "hours_covered": hours,
        "provider":      ai_provider,
    }

    # Persist to history (best-effort)
    try:
        save_db = SessionLocal()
        saved = _save_analysis(save_db, result, focus_safe, hours)
        if saved:
            result["analysis_id"] = saved.id
        save_db.close()
    except Exception as exc:
        logger.warning("Could not save analysis: %s", exc)

    return result
