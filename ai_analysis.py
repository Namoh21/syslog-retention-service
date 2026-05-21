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

# ── SIEM-CTI prompt (used for both Claude and local LLMs) ────────────────────

_SIEM_CTI_SYSTEM = """\
<agent_name>SIEM-CTI</agent_name>

<identity>
  Role: Elite Cyber Threat Intelligence analyst operating as a log analysis engine.
  Persona: Forensic, evidence-driven. Every finding anchored to exact log entries.
  No external tool access — analysis derived solely from provided log data.
</identity>

<mission>
  Objective: Ingest raw syslog/netflow data and produce structured JSON intelligence
  reports consumable by a home-built SIEM.
  Success: All IOCs extracted, every suspicious event mapped to MITRE ATT&CK,
  confidence scored, JSON valid and schema-compliant on every run.
</mission>

<context>
  Deployment: Home-built SIEM (standalone)
  Users: Solo analyst / homelab operator
  Input: Raw syslog and netflow logs — pasted or piped directly
  Output: JSON file returned to SIEM for reporting and dashboarding
  Compliance: No PII/PCI/PHI constraints
  Tool access: None — log data only, no enrichment APIs
</context>

<capabilities>
  Log parsing: syslog|netflow — identify format, source device, timestamp normalization
  IOC extraction: IPs|domains|URLs|hashes|user accounts|email addresses
  MITRE ATT&CK: Map tactics/techniques from log evidence without API — use trained knowledge
  Diamond Model: Infer adversary|capability|infrastructure|victim from log evidence only
  Severity rating: CRITICAL|HIGH|MEDIUM|LOW based on impact + confidence
  Timeline reconstruction: Chronological event sequencing from timestamps
  Confidence scoring: Per-finding float 0.0-1.0, flag any finding below 0.70
</capabilities>

<output_format>
  Format: Hybrid JSON — top-level metadata + events array + summary section
  Encoding: UTF-8, valid JSON, no markdown fences or prose outside JSON
  Schema:
  {
    "report_metadata": {
      "generated_at": "<ISO8601>",
      "log_source_format": "<syslog|netflow|mixed>",
      "log_timespan": {"earliest": "<ISO8601>", "latest": "<ISO8601>"},
      "total_events_analyzed": <int>,
      "total_iocs_extracted": <int>,
      "low_confidence_findings": <int>,
      "escalation_required": <bool>,
      "escalation_reason": "<string|null>"
    },
    "events": [
      {
        "event_id": "<string>",
        "timestamp": "<ISO8601>",
        "raw_log_excerpt": "<string>",
        "log_identification": {
          "format": "<syslog|netflow>",
          "generating_device": "<string|unknown>"
        },
        "iocs": [
          {
            "value": "<string>",
            "type": "<ip|domain|url|hash|email|account>",
            "classification": "<internal|external>",
            "malicious_pattern_flagged": <bool>,
            "confidence": <float 0.0-1.0>,
            "low_confidence": <bool>
          }
        ],
        "mitre_mappings": [
          {
            "tactic": "<string>",
            "technique_id": "<Txxxx>",
            "technique_name": "<string>",
            "evidence": "<exact log excerpt>",
            "confidence": <float 0.0-1.0>,
            "low_confidence": <bool>
          }
        ],
        "diamond_model": {
          "adversary": "<string|unknown>",
          "capability": "<string>",
          "infrastructure": "<string>",
          "victim": "<string>",
          "confidence": <float 0.0-1.0>,
          "low_confidence": <bool>
        },
        "threat_severity": {
          "rating": "<CRITICAL|HIGH|MEDIUM|LOW>",
          "impact_potential": "<string>",
          "confidence_level": <float 0.0-1.0>,
          "scope": "<string>"
        }
      }
    ],
    "summary": {
      "timeline": [
        {
          "timestamp": "<ISO8601>",
          "event_id": "<string>",
          "event": "<string>",
          "significance": "<string>"
        }
      ],
      "aggregate_iocs": [
        {
          "value": "<string>",
          "type": "<string>",
          "classification": "<internal|external>",
          "seen_in_events": ["<event_id>"],
          "malicious_pattern_flagged": <bool>
        }
      ],
      "top_mitre_techniques": [
        {
          "technique_id": "<Txxxx>",
          "technique_name": "<string>",
          "tactic": "<string>",
          "event_count": <int>
        }
      ],
      "overall_threat_severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "response_actions": {
        "immediate_containment": ["<string>"],
        "investigation_next_steps": ["<string>"],
        "long_term_remediation": ["<string>"],
        "additional_logs_needed": ["<string|null>"]
      }
    }
  }
</output_format>

<behavioral_rules>
  NEVER:
    speculate beyond log evidence
    | invent IOCs not present in provided data
    | omit low_confidence flag on any finding below 0.70
    | return prose — output is always valid JSON only
    | reference external threat intel not present in logs
    | suppress findings due to low confidence — include and flag
    | omit any schema key — use null or empty array if no data

  ALWAYS:
    anchor every finding to an exact log excerpt in the evidence field
    | set low_confidence:true on any finding with confidence below 0.70
    | set escalation_required:true when overall_threat_severity is CRITICAL
    | set escalation_required:true when majority of findings are below 0.70
    | populate escalation_reason with specific trigger condition
    | normalize all timestamps to ISO8601
    | classify every IOC as internal or external
    | deduplicate IOCs in summary.aggregate_iocs with seen_in_events references
    | rank summary.top_mitre_techniques by event_count descending
    | complete all schema sections every run
</behavioral_rules>

<tone>
  Forensic, precise, zero speculation. Every claim has a log citation.
  No narrative filler. Field values are declarative statements, not hedged observations.
  Assume reader has SOC-level threat intelligence literacy.
</tone>

<escalation>
  Triggers:
    overall_threat_severity == CRITICAL
    | majority of run findings have confidence below 0.70
  Action: set escalation_required:true + populate escalation_reason in report_metadata
  Scope: escalation is metadata only — all findings still included, no analysis halted
  Handoff: fields consumed by SIEM or analyst — no automated action taken by agent
</escalation>

Respond with ONLY a valid JSON object matching the schema above. No markdown fences, \
no prose, no explanation outside the JSON.\
"""

# Local LLM example — concrete filled instance of the schema (keeps small models on track)
_LOCAL_EXAMPLE = """{
  "report_metadata": {
    "generated_at": "2026-05-21T04:00:00Z",
    "log_source_format": "syslog",
    "log_timespan": {"earliest": "2026-05-21T03:00:00Z", "latest": "2026-05-21T04:00:00Z"},
    "total_events_analyzed": 150,
    "total_iocs_extracted": 3,
    "low_confidence_findings": 0,
    "escalation_required": false,
    "escalation_reason": null
  },
  "events": [
    {
      "event_id": "EVT-001",
      "timestamp": "2026-05-21T03:45:12Z",
      "raw_log_excerpt": "kernel: [UFW BLOCK] SRC=203.0.113.45 DST=192.168.1.1 PROTO=TCP DPT=22",
      "log_identification": {"format": "syslog", "generating_device": "UDM-Pro"},
      "iocs": [
        {"value": "203.0.113.45", "type": "ip", "classification": "external",
         "malicious_pattern_flagged": true, "confidence": 0.85, "low_confidence": false}
      ],
      "mitre_mappings": [
        {"tactic": "Initial Access", "technique_id": "T1190",
         "technique_name": "Exploit Public-Facing Application",
         "evidence": "SRC=203.0.113.45 DPT=22 repeated 47 times",
         "confidence": 0.80, "low_confidence": false}
      ],
      "diamond_model": {
        "adversary": "unknown external actor",
        "capability": "SSH brute-force scanning",
        "infrastructure": "203.0.113.45",
        "victim": "192.168.1.1:22",
        "confidence": 0.75, "low_confidence": false
      },
      "threat_severity": {
        "rating": "HIGH",
        "impact_potential": "Unauthorized gateway access if SSH exposed",
        "confidence_level": 0.82,
        "scope": "perimeter"
      }
    }
  ],
  "summary": {
    "timeline": [
      {"timestamp": "2026-05-21T03:45:12Z", "event_id": "EVT-001",
       "event": "SSH brute-force blocked from 203.0.113.45",
       "significance": "Persistent external scanning targeting SSH service"}
    ],
    "aggregate_iocs": [
      {"value": "203.0.113.45", "type": "ip", "classification": "external",
       "seen_in_events": ["EVT-001"], "malicious_pattern_flagged": true}
    ],
    "top_mitre_techniques": [
      {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
       "tactic": "Initial Access", "event_count": 1}
    ],
    "overall_threat_severity": "HIGH",
    "response_actions": {
      "immediate_containment": ["Block 203.0.113.45 at perimeter firewall immediately"],
      "investigation_next_steps": ["Review SSH auth logs for successful logins from this IP"],
      "long_term_remediation": ["Disable direct SSH, enforce VPN + jump host access only"],
      "additional_logs_needed": ["SSH authentication logs from target host"]
    }
  }
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
        ts  = e.received_at.strftime("%Y-%m-%dT%H:%M:%SZ") if e.received_at else "?"
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
        schema = analysis.get("_schema")
        if schema == "siem_cti":
            threat_level = analysis.get("threat_level")
            summary_text = analysis.get("_summary_text", "")
            findings_list = analysis.get("_findings_compat", [])
            immediate = analysis.get("_immediate_actions", [])
        else:
            threat_level = analysis.get("threat_level")
            summary_text = analysis.get("summary", "")
            findings_list = analysis.get("findings", [])
            immediate = analysis.get("immediate_actions", [])

        record = AIAnalysis(
            focus=focus[:256],
            hours_covered=int(hours),
            log_count=result.get("log_count", 0),
            threat_level=threat_level,
            summary=summary_text,
            immediate_actions_json=_json.dumps(immediate),
            findings_json=_json.dumps(findings_list),
        )
        db.add(record)
        db.flush()
        for f in findings_list:
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
            max_tokens=8192,
            system=_SIEM_CTI_SYSTEM,
            messages=[{"role": "user", "content": user_message}],
            timeout=120.0,
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
    user = (
        f"{user_message}\n\n"
        f"Analyze the log data above and respond with a JSON object matching the SIEM-CTI schema. "
        f"Use real data from the logs — do NOT copy example values. "
        f"Example structure (use real content, not these placeholders):\n"
        f"{_LOCAL_EXAMPLE}"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SIEM_CTI_SYSTEM},
            {"role": "user",   "content": user},
        ],
        "max_tokens": 8192,
        "temperature": 0.2,
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
    _SCHEMA_KEYS = {
        # new SIEM-CTI keys
        "report_metadata", "events",
        # old schema keys + LLM variants
        "summary", "threat_level", "findings", "immediate_actions",
        "long_term_recommendations", "executive_summary", "risk_level",
        "security_findings", "issues", "vulnerabilities", "recommendations",
    }
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


def _normalise_siem_cti(obj: dict) -> dict:
    """Pass through new SIEM-CTI schema; add backward-compat fields for DB persistence."""
    meta = obj.get("report_metadata", {})
    events = obj.get("events", []) or []
    summ = obj.get("summary", {}) or {}
    response_actions = summ.get("response_actions", {}) or {}

    # Derive threat level from summary
    tl_raw = str(summ.get("overall_threat_severity", "UNKNOWN")).upper().strip()
    threat_level = tl_raw if tl_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"

    # Build summary text for DB + banner subtitle
    total = meta.get("total_events_analyzed", len(events))
    ioc_count = meta.get("total_iocs_extracted", 0)
    top_techs = summ.get("top_mitre_techniques", []) or []
    top_tech_str = ", ".join(
        f"{t.get('technique_id','')} {t.get('technique_name','')}"
        for t in top_techs[:3]
    ) if top_techs else ""
    esc_note = " Escalation required." if meta.get("escalation_required") else ""
    summary_text = (
        f"Analyzed {total} events. Overall severity: {threat_level}. "
        f"{ioc_count} IOC(s) extracted."
        + (f" Top techniques: {top_tech_str}." if top_tech_str else "")
        + esc_note
    )

    # Build compat findings list from events (for DB rows)
    findings_compat = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        sev = ev.get("threat_severity", {}).get("rating", "LOW")
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "LOW"
        mitre = ev.get("mitre_mappings", []) or []
        iocs = ev.get("iocs", []) or []
        title = (mitre[0].get("technique_name") if mitre else None) or \
                (f"{iocs[0].get('type','').title()} IOC: {iocs[0].get('value','')}" if iocs else None) or \
                f"Event {ev.get('event_id', '')}"
        ioc_str = ", ".join(i.get("value", "") for i in iocs[:5])
        mitre_str = "; ".join(
            f"{m.get('technique_id','')} {m.get('technique_name','')}" for m in mitre[:3]
        )
        detail_parts = [ev.get("raw_log_excerpt", "")]
        if ioc_str:
            detail_parts.append(f"IOCs: {ioc_str}")
        if mitre_str:
            detail_parts.append(f"MITRE: {mitre_str}")
        dm = ev.get("diamond_model", {}) or {}
        if dm.get("capability"):
            detail_parts.append(f"Capability: {dm['capability']}")
        findings_compat.append({
            "severity":       sev,
            "title":          str(title)[:256],
            "detail":         "\n".join(detail_parts),
            "recommendation": "",
        })

    immediate = response_actions.get("immediate_containment", []) or []
    long_term  = response_actions.get("long_term_remediation", []) or []

    result = dict(obj)
    result["_schema"]           = "siem_cti"
    result["threat_level"]      = threat_level
    result["_summary_text"]     = summary_text
    result["_findings_compat"]  = findings_compat
    result["_immediate_actions"] = immediate if isinstance(immediate, list) else []
    result["_long_term_recs"]   = long_term if isinstance(long_term, list) else []

    logger.info("SIEM-CTI normalised: threat=%s events=%d iocs=%d techniques=%d",
                threat_level, len(events), ioc_count, len(top_techs))
    return result


def _normalise(obj: dict) -> dict:
    """Detect schema and normalise to canonical form."""

    # SIEM-CTI schema detection — must have report_metadata + events + summary
    if "report_metadata" in obj and "events" in obj and "summary" in obj:
        return _normalise_siem_cti(obj)

    # Legacy schema normalisation
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
            if v:
                return v
        return None

    raw_tl = _pick(_THREAT_KEYS) or ""
    tl_map = {"critical": "CRITICAL", "crit": "CRITICAL", "high": "HIGH",
              "medium": "MEDIUM", "moderate": "MEDIUM", "med": "MEDIUM",
              "low": "LOW", "info": "LOW", "minimal": "LOW"}
    threat_level = tl_map.get(str(raw_tl).lower().strip(), str(raw_tl).upper().strip())
    if threat_level not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        threat_level = "UNKNOWN"

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
    logger.info("Legacy normalised: threat=%s summary_len=%d findings=%d",
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

    log_text  = _format_entries(entries, local_llm=is_local)
    netflow   = _build_netflow_context(None, hours)
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

    try:
        save_db = SessionLocal()
        saved = _save_analysis(save_db, result, focus_safe, hours)
        if saved:
            result["analysis_id"] = saved.id
        save_db.close()
    except Exception as exc:
        logger.warning("Could not save analysis: %s", exc)

    return result
