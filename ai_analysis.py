"""
AI-powered analysis of syslog data.
Supports Anthropic (Claude) and local OpenAI-compatible LLMs (Ollama, LM Studio).
"""
import json as _json
import logging
import re as _re
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
        },
        "recommendation": "<specific, actionable step the analyst should take for this event — block the IP, isolate the host, rotate credentials, patch the service, etc. Be concrete: name the tool, command, or UI action.>"
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

<analyst_memory_protocol>
  The user message will include an ANALYST MEMORY block before the log data.
  This block contains three sections — process them in order before generating events:

  1. NETWORK CONTEXT
     Analyst-provided description of the environment: known hosts, VLANs, services,
     expected traffic patterns. Use this to correctly classify IOCs as internal/external
     and to avoid flagging expected behavior as suspicious.

  2. KNOWLEDGE BASE
     Categorized entries the analyst has saved. Treat these as ground truth for the
     environment. If a KB entry states a host, IP, service, or pattern is expected or
     known-good, do NOT flag it as an IOC or generate an event for it unless current
     logs show clear evidence that the known-good state has changed.

  3. RESOLVED FINDINGS (IMPLEMENTED | WORKING | DISMISSED)
     These are findings from prior analyses that the analyst has already actioned.
     RULE: Do NOT generate an event for any finding that matches a resolved item
     unless current logs show unambiguous evidence of REGRESSION (the same issue
     has returned after being fixed). If regression is detected, include the event
     and set significance to "REGRESSION — previously resolved on <date>".
     Items with status DISMISSED were intentionally accepted; never re-surface them.

  4. OPEN FINDINGS (still being tracked)
     These are known issues the analyst is already aware of. If they appear in the
     current logs, include them as events but note "RECURRING — open since <date>"
     in the significance field of the timeline entry. Do not suppress them — the
     analyst needs to see if they are escalating or stable.

  After processing analyst memory, apply it to filter false positives and avoid
  redundant findings before generating the events array.
</analyst_memory_protocol>

<grounding_rules>
  STRICT LOG-GROUNDING REQUIREMENT — enforced before any event is generated:

  Every event in the output MUST satisfy ALL of the following tests:

  1. RAW EXCERPT TEST
     raw_log_excerpt must be copied verbatim from a line in the === LOG DATA ===
     block. If you cannot locate the exact line, the event does not exist.

  2. TIMESTAMP TEST
     Every timestamp must come directly from the log line cited in raw_log_excerpt.
     RFC 3164 syslog lines (e.g. "Mar  8 14:29:59 host app: msg") do NOT contain
     a year. When the year is absent from the log line, derive it from the analysis
     window dates provided in the user message — do NOT invent a year from training
     data. If the year cannot be determined, use null rather than guessing.

  3. IOC TEST — no IP, domain, hash, or account may be added to iocs[] unless it
     appears VERBATIM in the raw_log_excerpt field of that same event.
     Specific non-IOC patterns (never add these as IOCs):
       • PID numbers (e.g. "PID 570652") — these are process IDs, not IOCs
       • Service/daemon names (e.g. "udapi-server", "coredns") — not IOCs
       • Unix socket paths (e.g. "/run/utm/.cd_dl.so") — not IOCs
       • Generic internal gateway IPs (e.g. 10.0.0.1) unless that exact IP
         string appears in the log line
     If the log line contains no IP address, the iocs array must be empty ([]).

  4. MITRE TEST — verify technique IDs against known ATT&CK:
     • T1021 = Remote Services (Initial Access / Lateral Movement)
     • TA0002 = Execution  |  TA0004 = Privilege Escalation
     • A systemd PID supervision mismatch is NOT privilege escalation —
       it is a service configuration/reliability issue (no MITRE mapping applies)
     • A socket connection error is NOT privilege escalation
     • Only map to MITRE when the log provides direct evidence of adversarial
       activity, not when a system or daemon behaves unexpectedly

  5. IMPACT TEST
     impact_potential must be derived from what the log line literally shows.
     A daemon notification mismatch → service supervision issue, not privilege
     escalation. A socket error → service degradation, not privilege escalation.
     A DNS query → network communication, not an attack.

  REJECTION RULE: If any event fails any of the five tests above, DROP that
  event entirely. An empty events array is correct when no qualifying log lines
  exist. Never pad the output with inferred or fabricated events.
</grounding_rules>

<behavioral_rules>
  NEVER:
    speculate beyond log evidence
    | invent IOCs not present in provided data
    | invent timestamps — every timestamp must come from an actual log line
    | generate an event whose raw_log_excerpt cannot be found verbatim in the log data
    | assign an impact or scope that is not directly supported by the cited log line
    | omit low_confidence flag on any finding below 0.70
    | return prose — output is always valid JSON only
    | reference external threat intel not present in logs
    | suppress findings due to low confidence — include and flag
    | omit any schema key — use null or empty array if no data
    | re-surface a finding with status IMPLEMENTED, WORKING, or DISMISSED
      unless clear log evidence of regression exists
    | generate events when the log data contains no qualifying entries —
      return an empty events array instead

  ALWAYS:
    apply the GROUNDING RULES before generating any event
    | read the ANALYST MEMORY block before analyzing log data
    | cross-reference every candidate finding against RESOLVED FINDINGS before including it
    | use NETWORK CONTEXT and KNOWLEDGE BASE to inform IOC classification
    | copy raw_log_excerpt verbatim from a line in the provided log data
    | derive all timestamps directly from the cited log line
    | set low_confidence:true on any finding with confidence below 0.70
    | set escalation_required:true when overall_threat_severity is CRITICAL
    | set escalation_required:true when majority of findings are below 0.70
    | populate escalation_reason with specific trigger condition
    | normalize all timestamps to ISO8601
    | classify every IOC as internal or external
    | deduplicate IOCs in summary.aggregate_iocs with seen_in_events references
    | rank summary.top_mitre_techniques by event_count descending
    | complete all schema sections every run
    | mark recurring open findings as "RECURRING" in timeline significance
    | mark regressions as "REGRESSION — previously resolved on <date>" in timeline significance
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

# ── Network Reliability Engineer agent ───────────────────────────────────────

_NRE_SYSTEM = """\
<agent_name>NRE-OPS</agent_name>

<identity>
  Role: Senior Network Reliability Engineer performing operational log review.
  Persona: Evidence-driven. Every finding anchored to exact log entries.
  Focus: Service health, availability, performance, and configuration — not security threats.
  No external tool access — analysis derived solely from provided log data.
</identity>

<mission>
  Objective: Ingest syslog/netflow data and produce a structured JSON operational health report
  consumable by a home-built SIEM. Identify service failures, degradation, resource exhaustion,
  configuration errors, and flapping conditions. Produce actionable remediation steps.
  Success: Every service issue mapped to a root cause category, JSON valid and schema-compliant.
</mission>

<context>
  Deployment: Home-built SIEM (standalone)
  Users: Solo operator / homelab admin
  Input: Raw syslog and netflow logs
  Output: JSON operational health report returned to SIEM for dashboarding
  Tool access: None — log data only
</context>

<capabilities>
  Log parsing: syslog|netflow — identify services, daemons, and devices from log signatures
  Service health: Detect crashes, restarts, hangs, connection failures, timeout patterns
  Resource analysis: Memory pressure, CPU spikes, disk full, connection pool exhaustion
  Configuration issues: Missing files, permission errors, invalid config, version mismatches
  Dependency mapping: Identify when service A fails because service B it depends on is down
  Flap detection: Identify services repeatedly cycling between UP/DOWN states
  Network reliability: DHCP failures, DNS resolution errors, interface errors, link flaps
  Trend detection: Gradually degrading metrics (memory leak, growing error rate) from log sequences
</capabilities>

<output_format>
  Format: Structured JSON — metadata + service_events array + summary
  Encoding: UTF-8, valid JSON, no markdown fences or prose outside JSON
  Schema:
  {
    "report_metadata": {
      "generated_at": "<ISO8601>",
      "log_source_format": "<syslog|netflow|mixed>",
      "log_timespan": {"earliest": "<ISO8601>", "latest": "<ISO8601>"},
      "total_events_analyzed": <int>,
      "services_affected": <int>,
      "critical_failures": <int>,
      "escalation_required": <bool>,
      "escalation_reason": "<string|null>"
    },
    "service_events": [
      {
        "event_id": "<string>",
        "timestamp": "<ISO8601>",
        "raw_log_excerpt": "<exact log line(s) that triggered this finding>",
        "service": "<daemon or service name>",
        "host": "<hostname or IP of the affected device>",
        "health_state": "<DOWN|DEGRADED|FLAPPING|RECOVERING|UNKNOWN>",
        "root_cause": {
          "category": "<crash|resource_exhaustion|config_error|dependency_failure|network_issue|unknown>",
          "evidence": "<exact log excerpt supporting this root cause>",
          "confidence": <float 0.0-1.0>,
          "low_confidence": <bool>
        },
        "impact": {
          "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
          "affected_systems": "<string — what users or systems are impacted>",
          "downstream_effects": ["<string — cascading failures or degraded functions>"]
        },
        "recurrence": {
          "is_recurring": <bool>,
          "occurrence_count": <int|null>,
          "pattern": "<string|null — e.g. every 60s, after heavy load, etc.>"
        },
        "recommendation": "<specific, actionable remediation step for this service event — restart the service, free disk space, fix the config, check the dependency. Name the exact command, file path, or UI action.>"
      }
    ],
    "summary": {
      "overall_health": "<CRITICAL|DEGRADED|WARNING|HEALTHY>",
      "top_failing_services": [
        {
          "service": "<string>",
          "host": "<string>",
          "event_count": <int>,
          "health_state": "<string>",
          "root_cause_category": "<string>"
        }
      ],
      "resource_pressure": {
        "memory": "<observation from logs or null>",
        "cpu": "<observation from logs or null>",
        "disk": "<observation from logs or null>",
        "network": "<observation from logs or null>"
      },
      "dependency_issues": [
        {
          "failed_dependency": "<string>",
          "affected_services": ["<string>"],
          "evidence": "<log excerpt>"
        }
      ],
      "response_actions": {
        "immediate_remediation": ["<string — specific action to restore service now>"],
        "investigation_steps": ["<string — what to check next>"],
        "long_term_fixes": ["<string — architectural or config changes to prevent recurrence>"],
        "monitoring_recommendations": ["<string — what to alert on going forward>"]
      }
    }
  }
</output_format>

<analyst_memory_protocol>
  The user message will include an ANALYST MEMORY block before the log data.
  Process it before generating service_events:
  1. NETWORK CONTEXT — use to understand expected service topology and normal behavior.
  2. KNOWLEDGE BASE — treat as ground truth. Do not flag known-good behavior as a failure.
  3. RESOLVED FINDINGS — do NOT re-surface issues already marked IMPLEMENTED or WORKING
     unless current logs show clear regression. DISMISSED items are never re-surfaced.
  4. OPEN FINDINGS — include as RECURRING if still present; note in recurrence.pattern.
</analyst_memory_protocol>

<grounding_rules>
  STRICT LOG-GROUNDING REQUIREMENT — enforced before any service_event is generated:

  Every service_event in the output MUST satisfy ALL of the following tests:

  1. RAW EXCERPT TEST
     raw_log_excerpt must be copied verbatim from a line in the === LOG DATA ===
     block. If you cannot locate the exact line, the event does not exist.

  2. TIMESTAMP TEST
     Every timestamp must come from the log line cited in raw_log_excerpt.
     RFC 3164 syslog lines (e.g. "Mar  8 14:29:59 host app: msg") do NOT contain
     a year. When the year is absent, derive it from the analysis window dates in
     the user message — do NOT invent a year from training data. Use null if
     the year cannot be determined.

  3. SERVICE/HOST TEST
     service name and host must appear in the cited log line. Acceptable sources:
     the app_name field (e.g. "systemd", "udapi-server"), the hostname field, or
     an explicit device identifier. Do not infer from general knowledge alone.

  4. ROOT CAUSE TEST
     root_cause.evidence must be a verbatim excerpt from the cited log line.
     root_cause.category must reflect only what the log line shows:
       • "Got notification message from PID X, but reception only permitted for
         main PID Y" → category: config_error (wrong Type=notify setup), NOT crash
       • A socket connection failure → dependency_failure
       • OOM/earlyoom message → resource_exhaustion
       • Service start/stop → not necessarily a failure

  REJECTION RULE: If any service_event fails any test above, DROP it entirely.
  An empty service_events array is correct when no qualifying log lines exist.
</grounding_rules>

<behavioral_rules>
  NEVER:
    speculate beyond log evidence
    | invent service names, hostnames, timestamps, or errors not present in the logs
    | generate a service_event whose raw_log_excerpt cannot be found verbatim in the log data
    | assign a root_cause or impact not directly supported by the cited log line
    | omit low_confidence flag on any finding with confidence below 0.70
    | return prose — output is always valid JSON only
    | flag security threats — that is the SIEM-CTI agent's domain
    | re-surface IMPLEMENTED, WORKING, or DISMISSED findings without regression evidence
    | omit any schema key — use null or empty array if no data
    | generate service_events when the log data contains no qualifying entries

  ALWAYS:
    apply the GROUNDING RULES before generating any service_event
    | read the ANALYST MEMORY block before analyzing log data
    | cross-reference every candidate finding against RESOLVED FINDINGS
    | copy raw_log_excerpt verbatim from a line in the provided log data
    | derive all timestamps directly from the cited log line
    | set low_confidence:true on any root_cause with confidence below 0.70
    | set escalation_required:true when overall_health is CRITICAL
    | populate escalation_reason when escalation_required is true
    | detect recurring patterns (same service failing repeatedly in the window)
    | identify dependency chains (service A fails because service B is down)
    | complete all schema sections every run
</behavioral_rules>

<tone>
  Operational, precise, evidence-based. Every claim has a log citation.
  Focus on what broke, why it broke, and how to fix it — not on threats or adversaries.
  Assume reader is a homelab operator comfortable with Linux services and networking.
</tone>

Respond with ONLY a valid JSON object matching the schema above. No markdown fences, \
no prose, no explanation outside the JSON.\
"""

_NRE_LOCAL_EXAMPLE = """\
STRUCTURAL EXAMPLE — REPLACE ALL VALUES WITH REAL DATA FROM THE LOGS ABOVE.
{
  "report_metadata": {
    "generated_at": "<ISO8601 now>",
    "log_source_format": "syslog",
    "log_timespan": {"earliest": "<first timestamp>", "latest": "<last timestamp>"},
    "total_events_analyzed": "<integer>",
    "services_affected": "<integer>",
    "critical_failures": "<integer>",
    "escalation_required": false,
    "escalation_reason": null
  },
  "service_events": [
    {
      "event_id": "SVC-001",
      "timestamp": "<from log>",
      "raw_log_excerpt": "<exact log line>",
      "service": "<daemon name from log>",
      "host": "<hostname or IP>",
      "health_state": "DEGRADED",
      "root_cause": {
        "category": "resource_exhaustion",
        "evidence": "<exact log line showing the resource issue>",
        "confidence": 0.85,
        "low_confidence": false
      },
      "impact": {
        "severity": "HIGH",
        "affected_systems": "<what systems or users are affected>",
        "downstream_effects": ["<cascading effect 1>"]
      },
      "recurrence": {
        "is_recurring": true,
        "occurrence_count": 5,
        "pattern": "<describe the pattern, e.g. every ~60s>"
      },
      "recommendation": "<specific remediation step from the log evidence, e.g. restart service X, free disk on /var, fix config at /etc/...>"
    }
  ],
  "summary": {
    "overall_health": "DEGRADED",
    "top_failing_services": [
      {"service": "<name>", "host": "<host>", "event_count": 3, "health_state": "DEGRADED", "root_cause_category": "resource_exhaustion"}
    ],
    "resource_pressure": {
      "memory": "<observation or null>",
      "cpu": null,
      "disk": null,
      "network": null
    },
    "dependency_issues": [],
    "response_actions": {
      "immediate_remediation": ["<specific action>"],
      "investigation_steps": ["<what to check>"],
      "long_term_fixes": ["<architectural fix>"],
      "monitoring_recommendations": ["<what to alert on>"]
    }
  }
}
END STRUCTURAL EXAMPLE\
"""

# ── Available agents ──────────────────────────────────────────────────────────

AGENTS = {
    "siem_cti": {
        "label":        "Cyber Threat Intelligence",
        "system":       _SIEM_CTI_SYSTEM,
        "local_example": None,   # set below after _LOCAL_EXAMPLE is defined
        "schema":       "siem_cti",
    },
    "nre": {
        "label":        "Network Reliability Engineer",
        "system":       _NRE_SYSTEM,
        "local_example": _NRE_LOCAL_EXAMPLE,
        "schema":       "nre",
    },
}

# Local LLM example — shows JSON structure only; values are placeholders, NOT real data.
# WARNING: every value below is fictional. The model MUST replace all of them with
# data extracted from the actual logs provided by the user. Do not copy these values.
_LOCAL_EXAMPLE = """\
STRUCTURAL EXAMPLE — REPLACE ALL VALUES WITH REAL DATA FROM THE LOGS ABOVE.
Do not copy IPs, timestamps, event IDs, or any other value from this example.
{
  "report_metadata": {
    "generated_at": "<ISO8601 timestamp of right now>",
    "log_source_format": "<syslog|netflow|mixed — from actual logs>",
    "log_timespan": {"earliest": "<earliest timestamp in logs>", "latest": "<latest timestamp in logs>"},
    "total_events_analyzed": "<integer — count of log lines analyzed>",
    "total_iocs_extracted": "<integer — count of unique IOCs found>",
    "low_confidence_findings": "<integer — count of findings below 0.70 confidence>",
    "escalation_required": false,
    "escalation_reason": null
  },
  "events": [
    {
      "event_id": "EVT-001",
      "timestamp": "<exact timestamp from the log entry>",
      "raw_log_excerpt": "<copy the exact log line that triggered this event>",
      "log_identification": {
        "format": "syslog",
        "generating_device": "<hostname or IP of the device that sent the log>"
      },
      "iocs": [
        {
          "value": "<IP, domain, hash, or account from the actual log>",
          "type": "ip",
          "classification": "<internal|external>",
          "malicious_pattern_flagged": true,
          "confidence": 0.85,
          "low_confidence": false
        }
      ],
      "mitre_mappings": [
        {
          "tactic": "<ATT&CK tactic name>",
          "technique_id": "<Txxxx>",
          "technique_name": "<technique name>",
          "evidence": "<exact excerpt from the log that supports this mapping>",
          "confidence": 0.80,
          "low_confidence": false
        }
      ],
      "diamond_model": {
        "adversary": "<inferred adversary or 'unknown'>",
        "capability": "<what capability the adversary used>",
        "infrastructure": "<IP or domain used as infrastructure>",
        "victim": "<target host or service>",
        "confidence": 0.75,
        "low_confidence": false
      },
      "threat_severity": {
        "rating": "HIGH",
        "impact_potential": "<what damage this could cause>",
        "confidence_level": 0.82,
        "scope": "<perimeter|internal|lateral|etc>"
      },
      "recommendation": "<specific action to take for this event, e.g. block the IP at the firewall, rotate the credential, isolate the host>"
    }
  ],
  "summary": {
    "timeline": [
      {
        "timestamp": "<from actual log>",
        "event_id": "EVT-001",
        "event": "<brief description of what happened>",
        "significance": "<why this matters>"
      }
    ],
    "aggregate_iocs": [
      {
        "value": "<actual IOC value from logs>",
        "type": "ip",
        "classification": "external",
        "seen_in_events": ["EVT-001"],
        "malicious_pattern_flagged": true
      }
    ],
    "top_mitre_techniques": [
      {
        "technique_id": "<Txxxx>",
        "technique_name": "<name>",
        "tactic": "<tactic>",
        "event_count": 1
      }
    ],
    "overall_threat_severity": "HIGH",
    "response_actions": {
      "immediate_containment": ["<specific action based on actual finding>"],
      "investigation_next_steps": ["<what to investigate next>"],
      "long_term_remediation": ["<strategic fix>"],
      "additional_logs_needed": ["<what other logs would help>"]
    }
  }
}
END STRUCTURAL EXAMPLE — output must contain ONLY real data from the logs, not the above.\
"""

# Wire SIEM-CTI local example now that it's defined
AGENTS["siem_cti"]["local_example"] = _LOCAL_EXAMPLE


def resolve_agent(agent_key: str, db=None):
    """Resolve agent config from DB (custom/override) or built-in AGENTS dict."""
    from database import CustomAgent, SessionLocal
    own = db is None
    if own:
        db = SessionLocal()
    try:
        record = db.query(CustomAgent).filter_by(key=agent_key).first()
        if record:
            return {
                "label":         record.label,
                "system":        record.system_prompt,
                "local_example": AGENTS.get(record.schema_type, {}).get("local_example") or _LOCAL_EXAMPLE,
                "schema":        record.schema_type if record.schema_type != "auto" else agent_key,
                "use_kb_history": record.use_kb_history,
            }
    except Exception:
        pass
    finally:
        if own:
            db.close()
    cfg = AGENTS.get(agent_key) or AGENTS["siem_cti"]
    return dict(cfg, use_kb_history=True)

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
        src = e.src_ip or e.log_source_ip or "?"
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
    """
    Build the ANALYST MEMORY block consumed by the SIEM-CTI agent.

    Produces four clearly-labelled sections so the agent can:
    - Use network context + KB to avoid false positives
    - Skip re-surfacing RESOLVED findings (IMPLEMENTED / WORKING / DISMISSED)
    - Mark OPEN findings as RECURRING when they appear again
    """
    from database import AIAnalysis, AIRecommendation, AINetworkContext, AIContextEntry
    from collections import defaultdict

    has_content = False
    lines: list[str] = []

    # ── 1. Network context ────────────────────────────────────────────────────
    ctx = db.query(AINetworkContext).filter_by(id=1).first()
    if ctx and ctx.content and ctx.content.strip():
        lines.append("=== ANALYST MEMORY: NETWORK CONTEXT ===")
        lines.append("The analyst has described this environment. Use it to classify")
        lines.append("IOCs and avoid flagging expected behavior as suspicious.")
        lines.append("")
        lines.append(ctx.content.strip())
        lines.append("=== END NETWORK CONTEXT ===\n")
        has_content = True

    # ── 2. Knowledge base ─────────────────────────────────────────────────────
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
        lines.append("=== ANALYST MEMORY: KNOWLEDGE BASE ===")
        lines.append("These entries are analyst-verified ground truth for this environment.")
        lines.append("Do NOT flag IPs, services, or patterns described here as suspicious")
        lines.append("unless the current logs show the expected behavior has clearly changed.")
        lines.append("")
        for cat, entries in by_cat.items():
            lines.append(f"[{cat.upper().replace('_', ' ')}]")
            for e in entries:
                lines.append(f"  {e.title}:")
                for ln in e.content.strip().splitlines():
                    lines.append(f"    {ln}")
            lines.append("")
        lines.append("=== END KNOWLEDGE BASE ===\n")
        has_content = True

    # ── 3 & 4. Past analyses — split resolved vs open ─────────────────────────
    past = (
        db.query(AIAnalysis)
        .order_by(AIAnalysis.analyzed_at.desc())
        .limit(10)
        .all()
    )

    resolved_lines: list[str] = []
    open_lines: list[str] = []

    _RESOLVED_STATUSES = {"implemented", "working", "dismissed"}

    for a in reversed(past):
        ts = a.analyzed_at.strftime("%Y-%m-%d %H:%M UTC") if a.analyzed_at else "?"
        recs = db.query(AIRecommendation).filter_by(analysis_id=a.id).all()
        for r in recs:
            status = (r.status or "open").lower()
            note = f" | analyst note: {r.user_notes.strip()}" if r.user_notes and r.user_notes.strip() else ""
            sev  = f" | severity: {r.severity}" if r.severity else ""
            entry = f"  - [{ts}]{sev} {r.title or '(untitled)'}{note}"
            if status in _RESOLVED_STATUSES:
                resolved_lines.append(f"  STATUS: {status.upper()}")
                resolved_lines.append(entry)
            else:
                open_lines.append(f"  STATUS: OPEN (first seen {ts})")
                open_lines.append(entry)

    if resolved_lines:
        lines.append("=== ANALYST MEMORY: RESOLVED FINDINGS — DO NOT RE-SURFACE ===")
        lines.append("These findings were actioned by the analyst. Do NOT generate an")
        lines.append("event for any of these unless current logs show clear regression")
        lines.append("(issue returned after being fixed). DISMISSED items must never")
        lines.append("be re-surfaced. If regression: note 'REGRESSION' in significance.")
        lines.append("")
        lines.extend(resolved_lines)
        lines.append("=== END RESOLVED FINDINGS ===\n")
        has_content = True

    if open_lines:
        lines.append("=== ANALYST MEMORY: OPEN FINDINGS — STILL BEING TRACKED ===")
        lines.append("These findings are known and being actively tracked. If they appear")
        lines.append("in the current logs, include them as events but add 'RECURRING' to")
        lines.append("the timeline significance field. Do not suppress them.")
        lines.append("")
        lines.extend(open_lines)
        lines.append("=== END OPEN FINDINGS ===\n")
        has_content = True

    return "\n".join(lines) + "\n" if has_content else ""


async def _build_unifi_config_context() -> str:
    """
    Build UniFi config context block for AI analysis.
    Uses the most recent DB snapshot (< 10 min) to avoid live API calls on every
    analysis run. Falls back to live fetch if no recent snapshot exists.
    """
    import json as _json
    cfg: dict = {}
    try:
        from database import UnifiConfigSnapshot, SessionLocal
        db = SessionLocal()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
            row = (db.query(UnifiConfigSnapshot)
                   .filter(UnifiConfigSnapshot.taken_at >= cutoff)
                   .order_by(UnifiConfigSnapshot.taken_at.desc())
                   .first())
            if row:
                cfg = _json.loads(row.config_json)
                logger.info("UniFi config context: using DB snapshot from %s", row.taken_at)
        finally:
            db.close()
    except Exception:
        pass

    if not cfg:
        try:
            from unifi_poller import fetch_config_snapshot
            cfg = await fetch_config_snapshot()
            logger.info("UniFi config context: fetched live from API")
        except Exception as exc:
            logger.warning("UniFi config context failed: %s", exc)
            return ""

    if not cfg:
        return ""

    lines = ["=== UNIFI NETWORK CONFIGURATION (live, read from API) ===",
             "Use this to make specific, rule-referenced recommendations.",
             "When recommending changes, name the exact rule, VLAN, or setting.",
             ""]

    # ── Firewall rules ────────────────────────────────────────────────────────
    fw = cfg.get("firewall_rules", [])
    if fw:
        lines.append("FIREWALL RULES:")
        for r in fw:
            enabled = "" if r.get("enabled", True) else " [DISABLED]"
            action  = r.get("action", "?").upper()
            name    = r.get("name", "unnamed")
            ruleset = r.get("ruleset", "")
            idx     = r.get("rule_index", "")
            src     = r.get("src_firewallgroup_ids") or r.get("src_address", "any")
            dst     = r.get("dst_firewallgroup_ids") or r.get("dst_address", "any")
            proto   = r.get("protocol", "all")
            dst_port = r.get("dst_port", "")
            port_str = f" dport:{dst_port}" if dst_port else ""
            lines.append(f"  [{action}]{enabled} {ruleset} #{idx} \"{name}\" "
                         f"src={src} dst={dst} proto={proto}{port_str}")
        lines.append("")

    # ── Firewall groups ───────────────────────────────────────────────────────
    groups = cfg.get("firewall_groups", [])
    if groups:
        lines.append("FIREWALL GROUPS (IP/port sets referenced by rules):")
        for g in groups:
            members = g.get("group_members", [])
            gtype   = g.get("group_type", "")
            lines.append(f"  \"{g.get('name','')}\" [{gtype}]: "
                         f"{', '.join(str(m) for m in members[:8])}"
                         f"{'…' if len(members) > 8 else ''}")
        lines.append("")

    # ── Port forwards ─────────────────────────────────────────────────────────
    pf = cfg.get("port_forwards", [])
    if pf:
        lines.append("PORT FORWARDS (internet-exposed services — HIGH SECURITY RELEVANCE):")
        for r in pf:
            enabled   = "" if r.get("enabled", True) else " [DISABLED]"
            name      = r.get("name", "unnamed")
            proto     = r.get("proto", "tcp")
            dst_port  = r.get("dst_port", "?")
            fwd_ip    = r.get("fwd", "?")
            fwd_port  = r.get("fwd_port", dst_port)
            src_filter = r.get("src", "any")
            lines.append(f"  {proto.upper()}/{dst_port} → {fwd_ip}:{fwd_port}{enabled} "
                         f"\"{name}\" (src filter: {src_filter})")
        lines.append("")

    # ── Networks / VLANs ──────────────────────────────────────────────────────
    nets = cfg.get("networks", [])
    if nets:
        lines.append("NETWORKS / VLANs:")
        for n in nets:
            purpose  = n.get("purpose", "")
            name     = n.get("name", "")
            subnet   = n.get("ip_subnet", "")
            vlan_id  = n.get("vlan", "")
            dhcp     = "DHCP" if n.get("dhcpd_enabled") else "no-DHCP"
            vlan_str = f" VLAN{vlan_id}" if vlan_id else ""
            lines.append(f"  \"{name}\"{vlan_str} {subnet} [{purpose}] {dhcp}")
        lines.append("")

    # ── WiFi ──────────────────────────────────────────────────────────────────
    wlans = cfg.get("wifi_networks", [])
    if wlans:
        lines.append("WIFI NETWORKS:")
        for w in wlans:
            security = w.get("security", "open")
            vlan     = w.get("vlan_id", "default")
            enabled  = "" if w.get("enabled", True) else " [DISABLED]"
            lines.append(f"  SSID \"{w.get('name','')}\" security={security} "
                         f"vlan={vlan}{enabled}")
        lines.append("")

    # ── IPS settings ─────────────────────────────────────────────────────────
    ips = cfg.get("ips_settings", {})
    if ips:
        lines.append("IPS / THREAT DETECTION SETTINGS:")
        lines.append(f"  Enabled: {ips.get('enabled', False)}")
        lines.append(f"  Mode: {ips.get('ips_mode', 'unknown')}")
        cats = ips.get("suppression", {}).get("categories", [])
        if cats:
            lines.append(f"  Suppressed categories: {', '.join(str(c) for c in cats)}")
        lines.append("")

    # ── Devices ───────────────────────────────────────────────────────────────
    devs = cfg.get("devices", [])
    if devs:
        lines.append("MANAGED DEVICES:")
        for d in devs:
            lines.append(f"  {d.get('type','?')} \"{d.get('name','?')}\" "
                         f"ip={d.get('ip','?')} model={d.get('model','?')} "
                         f"fw={d.get('version','?')}")
        lines.append("")

    # ── Static routes ─────────────────────────────────────────────────────────
    routes = cfg.get("static_routes", [])
    if routes:
        lines.append("STATIC ROUTES:")
        for r in routes:
            lines.append(f"  {r.get('network','')} via {r.get('nexthop','')} "
                         f"[\"{r.get('name','')}\"]")
        lines.append("")

    lines.append("=== END UNIFI CONFIGURATION ===\n")
    return "\n".join(lines)


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


# ── register_log_source tool ─────────────────────────────────────────────────
# Offered to Claude when unknown-event-type entries are present in the batch.
# Claude can call this to register a new normalizer that takes effect immediately.

_REGISTER_PARSER_TOOL = {
    "name": "register_log_source",
    "description": (
        "Register a new syslog normalizer when you identify event_type='unknown' messages "
        "that belong to a recognizable device or application (e.g. a NAS, UPS, printer, "
        "camera system, or network appliance). The parser is stored in the database and "
        "activates immediately for all future log normalization — no code deployment needed."
    ),
    "input_schema": {
        "type": "object",
        "required": ["name", "app_keywords", "patterns"],
        "properties": {
            "name": {
                "type": "string",
                "description": "Unique snake_case identifier, e.g. 'synology_dsm', 'hp_printer'",
            },
            "description": {
                "type": "string",
                "description": "Human-readable description of the device or application",
            },
            "app_keywords": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Substrings that identify this source in a syslog message. "
                    "At least one must be present for the parser to run. "
                    "Use app-name values from the log lines you observed."
                ),
            },
            "patterns": {
                "type": "array",
                "description": "Ordered list of regex rules. First match wins.",
                "items": {
                    "type": "object",
                    "required": ["regex", "event_type"],
                    "properties": {
                        "regex": {
                            "type": "string",
                            "description": "Python regex with capture groups matching the message body",
                        },
                        "event_type": {
                            "type": "string",
                            "description": "Normalized event type, e.g. 'ups_power_fail', 'printer_job'",
                        },
                        "action": {
                            "type": "string",
                            "enum": ["ALLOW", "BLOCK", "ALERT"],
                            "description": "Optional action to assign",
                        },
                        "fields": {
                            "type": "object",
                            "description": (
                                "Maps NormalizedFields attribute names to 1-based capture group "
                                "indices. Valid names: src_ip, dst_ip, src_port, dst_port, "
                                "protocol, user, hostname, domain, mac_address, rule_name, url_category"
                            ),
                            "additionalProperties": {"type": "integer"},
                        },
                    },
                },
            },
        },
    },
}


async def _execute_register_parser(tool_input: dict, db) -> str:
    """Execute the register_log_source tool call: validate, persist, hot-reload."""
    from database import CustomParser
    from normalizer import load_custom_parsers

    for p in tool_input.get("patterns", []):
        try:
            _re.compile(p["regex"])
        except _re.error as exc:
            return f"Invalid regex '{p['regex']}': {exc}"

    record = CustomParser(
        name=tool_input["name"],
        description=tool_input.get("description", ""),
        app_keywords=_json.dumps(tool_input["app_keywords"]),
        patterns=_json.dumps(tool_input["patterns"]),
        enabled=True,
        created_by="ai_agent",
    )
    try:
        db.merge(record)
        db.commit()
    except Exception as exc:
        db.rollback()
        return f"Database error saving parser '{tool_input['name']}': {exc}"

    # Hot-reload all enabled parsers so the new one is active immediately
    try:
        from database import CustomParser as _CP
        all_enabled = db.query(_CP).filter_by(enabled=True).all()
        load_custom_parsers([
            {
                "app_keywords": _json.loads(r.app_keywords),
                "patterns":     _json.loads(r.patterns),
                "enabled":      True,
            }
            for r in all_enabled
        ])
    except Exception as exc:
        logger.warning("Custom parser hot-reload failed: %s", exc)

    n_patterns = len(tool_input["patterns"])
    logger.info("AI registered new log source parser '%s' with %d pattern(s)", tool_input["name"], n_patterns)
    return (
        f"Parser '{tool_input['name']}' registered with {n_patterns} pattern(s). "
        f"Active immediately for all incoming logs."
    )


# ── LLM callers ───────────────────────────────────────────────────────────────

async def _call_anthropic(api_key: str, model: str, user_message: str, agent_cfg: dict, *, db=None, enable_tools: bool = False) -> str:
    client = anthropic.AsyncAnthropic(api_key=api_key)
    logger.info("Calling Anthropic API — model=%s agent=%s tools=%s", model, agent_cfg.get("schema"), enable_tools)

    messages = [{"role": "user", "content": user_message}]
    tools = [_REGISTER_PARSER_TOOL] if enable_tools else anthropic.NOT_GIVEN

    try:
        for _iteration in range(5):  # cap tool-use iterations
            response = await client.messages.create(
                model=model,
                max_tokens=8192,
                system=agent_cfg["system"],
                messages=messages,
                tools=tools,
                timeout=120.0,
            )
            logger.info("Anthropic response — stop_reason=%s iteration=%d", response.stop_reason, _iteration)

            if response.stop_reason != "tool_use":
                text = next((b.text for b in response.content if hasattr(b, "text")), "")
                logger.info("Anthropic final response — %d chars", len(text))
                return text

            # Process tool calls
            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                if block.name == "register_log_source" and db is not None:
                    result_text = await _execute_register_parser(block.input, db)
                else:
                    result_text = f"Tool '{block.name}' is not available in this context."
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })
                logger.info("Tool '%s' executed: %s", block.name, result_text[:120])

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        # Exhausted iterations without a final text response
        logger.warning("Anthropic tool loop exhausted without final response")
        return ""

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


async def _call_local_llm(base_url: str, model: str, user_message: str, agent_cfg: dict) -> str:
    import httpx as _httpx
    example = agent_cfg.get("local_example") or _LOCAL_EXAMPLE
    user = (
        f"{user_message}\n\n"
        f"Produce a JSON report for the log data above.\n"
        f"CRITICAL GROUNDING RULES — violations invalidate the entire response:\n"
        f"  1. Every raw_log_excerpt MUST be copied verbatim from a line in the log data above.\n"
        f"  2. Every timestamp MUST come from the log line you quoted — never invent dates.\n"
        f"  3. Every IP, hostname, and identifier MUST appear in the quoted log line.\n"
        f"  4. Impact and scope MUST reflect only what the log line actually shows.\n"
        f"  5. If you cannot find a qualifying log line, output an empty events array.\n"
        f"     Do NOT copy values from the schema example below.\n\n"
        f"Schema structure (placeholders only — replace every field with real log data):\n"
        f"{example}"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": agent_cfg["system"]},
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
        # SIEM-CTI keys
        "report_metadata", "events",
        # NRE keys
        "service_events", "service_health",
        # legacy schema keys + LLM variants
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
            "recommendation": ev.get("recommendation", ""),
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


def _normalise_nre(obj: dict) -> dict:
    """Pass through NRE schema; add backward-compat fields for DB persistence."""
    meta    = obj.get("report_metadata", {}) or {}
    events  = obj.get("service_events", []) or []
    summ    = obj.get("summary", {}) or {}
    ra      = summ.get("response_actions", {}) or {}

    health_raw = str(summ.get("overall_health", "UNKNOWN")).upper()
    # Map NRE health → threat_level equivalent for banner + DB
    health_to_tl = {"CRITICAL": "CRITICAL", "DEGRADED": "HIGH",
                    "WARNING": "MEDIUM", "HEALTHY": "LOW"}
    threat_level = health_to_tl.get(health_raw, "UNKNOWN")

    total     = meta.get("total_events_analyzed", len(events))
    affected  = meta.get("services_affected", 0)
    failures  = meta.get("critical_failures", 0)
    summary_text = (
        f"Analyzed {total} events. Overall health: {health_raw}. "
        f"{affected} service(s) affected, {failures} critical failure(s)."
        + (" Escalation required." if meta.get("escalation_required") else "")
    )

    # Compat findings from service_events
    findings_compat = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        sev = (ev.get("impact") or {}).get("severity", "LOW")
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "LOW"
        rc = ev.get("root_cause", {}) or {}
        rec = ev.get("recurrence", {}) or {}
        detail_parts = [ev.get("raw_log_excerpt", "")]
        if rc.get("category"):
            detail_parts.append(f"Root cause: {rc['category']}")
        if rc.get("evidence") and rc["evidence"] != ev.get("raw_log_excerpt"):
            detail_parts.append(f"Evidence: {rc['evidence']}")
        if rec.get("is_recurring") and rec.get("pattern"):
            detail_parts.append(f"Pattern: {rec['pattern']} ({rec.get('occurrence_count','?')}x)")
        affected_sys = (ev.get("impact") or {}).get("affected_systems", "")
        findings_compat.append({
            "severity":       sev,
            "title":          f"{ev.get('service','?')} — {ev.get('health_state','?')} on {ev.get('host','?')}",
            "detail":         "\n".join(detail_parts),
            "recommendation": ev.get("recommendation", ""),
        })

    immediate = ra.get("immediate_remediation", []) or []
    long_term  = ra.get("long_term_fixes", []) or []

    result = dict(obj)
    result["_schema"]            = "nre"
    result["threat_level"]       = threat_level
    result["_summary_text"]      = summary_text
    result["_findings_compat"]   = findings_compat
    result["_immediate_actions"] = immediate if isinstance(immediate, list) else []
    result["_long_term_recs"]    = long_term if isinstance(long_term, list) else []

    logger.info("NRE normalised: health=%s events=%d services_affected=%d",
                health_raw, len(events), affected)
    return result


def _normalise(obj: dict) -> dict:
    """Detect schema and normalise to canonical form."""

    # SIEM-CTI schema detection — must have report_metadata + events + summary
    if "report_metadata" in obj and "events" in obj and "summary" in obj:
        return _normalise_siem_cti(obj)

    # NRE schema detection — has service_events (or service_health alias)
    if "service_events" in obj or "service_health" in obj:
        if "service_health" in obj and "service_events" not in obj:
            obj = dict(obj); obj["service_events"] = obj.pop("service_health")
        return _normalise_nre(obj)

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
    agent: str = "siem_cti",
    focus: str = "security",
    hours: float = 24,
    include_unifi_config: bool = False,
    db=None,
) -> dict[str, Any]:
    import json as _json
    from database import get_service_setting, SessionLocal

    ai_provider  = get_service_setting("ai_provider") or "anthropic"
    is_local     = ai_provider == "local"

    # Resolve agent — check DB for custom/override, fall back to built-in
    own_session = db is None
    if own_session:
        db = SessionLocal()
    agent_cfg = resolve_agent(agent, db)
    use_kb = agent_cfg.get("use_kb_history", True)

    try:
        history_block = _build_history_context(db) if use_kb else ""
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

    # Optionally prepend live UniFi configuration for config-aware analysis
    unifi_cfg_block = ""
    if include_unifi_config:
        try:
            unifi_cfg_block = await _build_unifi_config_context()
            if unifi_cfg_block:
                logger.info("UniFi config context included (%d chars)", len(unifi_cfg_block))
        except Exception as exc:
            logger.warning("Could not fetch UniFi config context: %s", exc)

    focus_safe = (focus or "security threats and anomalies")[:200]

    memory_instruction = (
        "STEP 1 — Read all ANALYST MEMORY sections above before analyzing any logs.\n"
        "STEP 2 — Cross-reference every candidate finding against RESOLVED FINDINGS.\n"
        "          Skip any finding that matches a resolved item (no regression in logs).\n"
        "          Skip any finding that matches a DISMISSED item unconditionally.\n"
        "STEP 3 — Use NETWORK CONTEXT and KNOWLEDGE BASE to classify IOCs and filter\n"
        "          known-good traffic before generating events.\n"
        "STEP 4 — Analyze the log data below and produce the JSON report.\n"
    ) if (history_block and use_kb) else ""

    window_year = datetime.now(timezone.utc).year
    grounding_reminder = (
        f"ANALYSIS WINDOW: {hours}h ending now. Current year: {window_year}.\n"
        f"Use {window_year} as the year for any RFC 3164 log lines that lack a year field.\n"
        "GROUNDING ENFORCEMENT: Every event you generate must be directly traceable to a\n"
        "specific line in the === LOG DATA === block below. Before including any event:\n"
        "  • Can you copy raw_log_excerpt verbatim from a line in the log data? If NO → drop it.\n"
        "  • Does the timestamp come from that same log line? If NO → drop it.\n"
        "  • Do ALL IPs in iocs[] appear verbatim in that log line? If NO → remove them.\n"
        "  • If the log line has no IP address, iocs[] must be empty.\n"
        "  • Is the impact derived only from what that log line actually shows? If NO → revise it.\n"
        "  • Is each MITRE technique a correct match verified against known ATT&CK IDs? If NO → remove it.\n"
        "An empty events array is correct when no qualifying log lines exist. Do not fabricate.\n"
    )

    config_instruction = (
        "UNIFI CONFIGURATION CONTEXT: The section above contains the live UniFi network "
        "configuration fetched directly from the controller API. When making recommendations:\n"
        "  • Reference specific rule names, VLAN names, and settings by their exact names\n"
        "  • Identify rules that should exist but are missing\n"
        "  • Flag port forwards that are unnecessary or misconfigured\n"
        "  • Cross-reference log events against the firewall rules that should have caught them\n"
        "  • Check IPS settings against observed threat categories in the logs\n"
        "  • For each recommendation, state the exact config change needed (rule name, action, "
        "source/destination group) so the analyst can implement it directly in the UniFi UI\n"
    ) if unifi_cfg_block else ""

    user_message = (
        f"{history_block}"
        f"{memory_instruction}"
        f"{unifi_cfg_block}"
        f"{config_instruction}"
        f"{grounding_reminder}"
        f"\nAnalyze the following {len(entries)} syslog entries from the last {hours}h. "
        f"Focus on: {focus_safe}.\n\n"
        f"=== LOG DATA ===\n{log_text}\n=== END LOG DATA ==="
    )

    logger.info("Starting analysis — provider=%s entries=%d hours=%s focus=%s",
                ai_provider, len(entries), hours, focus_safe)

    has_unknown = any(getattr(e, "event_type", None) == "unknown" for e in entries)

    if is_local:
        base_url = get_service_setting("ai_local_url") or ""
        model    = get_service_setting("ai_local_model") or "llama3.2"
        if not base_url:
            return {"error": "Local LLM URL not configured. Set it in Settings > AI Configuration.",
                    "log_count": len(entries)}
        try:
            raw_text = await _call_local_llm(base_url, model, user_message, agent_cfg)
        except Exception as exc:
            logger.error("Local LLM error: %s", exc)
            return {"error": f"Local LLM error: {exc}", "log_count": len(entries)}
    else:
        api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
        if not api_key:
            return {"error": "Anthropic API key not configured. Add it in Settings > AI Configuration.",
                    "log_count": len(entries)}
        model = get_service_setting("claude_model") or settings.claude_model or "claude-sonnet-4-6"
        # Open a persistent DB session for tool execution (parser registration)
        tool_db = SessionLocal() if has_unknown else None
        try:
            raw_text = await _call_anthropic(
                api_key, model, user_message, agent_cfg,
                db=tool_db,
                enable_tools=has_unknown,
            )
        except anthropic.RateLimitError:
            logger.warning("Anthropic rate limit hit")
            if tool_db:
                tool_db.close()
            return {"error": ("Rate limit reached. Try a shorter time window or reduce "
                              "'Max logs per AI analysis' in Settings → Service Configuration. "
                              "Wait 60 seconds and try again."),
                    "log_count": len(entries)}
        except anthropic.AuthenticationError:
            if tool_db:
                tool_db.close()
            return {"error": "Anthropic API key is invalid or expired. Update it in Service Settings.",
                    "log_count": len(entries)}
        except anthropic.NotFoundError:
            if tool_db:
                tool_db.close()
            return {"error": f"Model '{model}' not found. Update the Claude model in Service Settings.",
                    "log_count": len(entries)}
        except anthropic.APIError as exc:
            logger.error("Anthropic API error: %s", exc)
            if tool_db:
                tool_db.close()
            return {"error": f"Anthropic API error: {exc}", "log_count": len(entries)}
        finally:
            if tool_db:
                tool_db.close()

    logger.info("Raw response (first 500 chars): %s", raw_text[:500])
    analysis = _extract_json(raw_text)

    result = {
        "analysis":      analysis,
        "log_count":     len(entries),
        "analyzed_at":   datetime.now(timezone.utc).isoformat(),
        "model":         model,
        "hours_covered": hours,
        "provider":             ai_provider,
        "agent":               agent,
        "agent_label":         agent_cfg["label"],
        "unifi_config_used":   bool(unifi_cfg_block),
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
