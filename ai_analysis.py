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

_SYSTEM_PROMPT = """\
You are a network security analyst reviewing syslog data from a Unifi Dream Machine \
(UDM) and associated network devices. Your job is to:

1. Identify security threats, anomalies, and suspicious patterns in the log data.
2. Highlight configuration weaknesses or misconfigurations.
3. Surface high-severity events (Emergency, Alert, Critical, Error) for immediate attention.
4. Provide concrete, actionable recommendations to improve network security.

Format your response as structured JSON with these keys:
{
  "summary": "<2-3 sentence executive summary>",
  "threat_level": "<LOW | MEDIUM | HIGH | CRITICAL>",
  "findings": [
    {"severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>", "title": "...", "detail": "...", "recommendation": "..."}
  ],
  "immediate_actions": ["<action 1>", "<action 2>"],
  "long_term_recommendations": ["<rec 1>", "<rec 2>"]
}

Be specific and reference actual log entries where relevant.
"""


def _format_entries(entries: list[SyslogEntry]) -> str:
    lines = []
    for e in entries:
        sev = SEVERITY_NAMES[e.severity] if e.severity is not None and e.severity < 8 else str(e.severity)
        fac = FACILITY_NAMES[e.facility] if e.facility is not None and e.facility < len(FACILITY_NAMES) else str(e.facility)
        ts = e.received_at.strftime("%Y-%m-%d %H:%M:%S UTC") if e.received_at else "unknown"
        lines.append(
            f"[{ts}] [{sev}] [{fac}] {e.source_ip or '?'} {e.hostname or ''} "
            f"{e.app_name or ''}: {e.message or ''}"
        )
    return "\n".join(lines)


async def analyze_logs(
    entries: list[SyslogEntry],
    *,
    focus: str = "security",
    hours: int = 24,
) -> dict[str, Any]:
    from database import get_service_setting
    api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
    if not api_key:
        return {
            "error": "Anthropic API key not configured. Add it in Settings > AI Configuration.",
            "log_count": len(entries),
        }

    client = anthropic.Anthropic(api_key=api_key)
    claude_model = get_service_setting("claude_model") or settings.claude_model
    log_text = _format_entries(entries)
    focus_safe = focus[:200] if focus else "security threats and anomalies"

    user_message = (
        f"Please analyze the following {len(entries)} syslog entries from the last {hours} hours. "
        f"Focus on: {focus_safe}.\n\n"
        f"=== LOG DATA ===\n{log_text}\n=== END LOG DATA ==="
    )

    try:
        response = client.messages.create(
            model=claude_model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text

        # Try to parse as JSON; fall back to returning raw text
        import json
        try:
            analysis = json.loads(raw_text)
        except json.JSONDecodeError:
            # Claude returned narrative — wrap it
            analysis = {"summary": raw_text, "raw": True}

        return {
            "analysis": analysis,
            "log_count": len(entries),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "model": claude_model,
            "hours_covered": hours,
        }
    except anthropic.APIError as exc:
        logger.error("Anthropic API error: %s", exc)
        return {"error": str(exc), "log_count": len(entries)}
