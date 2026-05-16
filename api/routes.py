"""
All REST API routes for the syslog retention service.
"""
import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Optional

import csv
import io

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

# ── Background analysis job store ────────────────────────────────────────────
# job_id -> {status, result, started_at, username}
# status: "running" | "done" | "error"
_analysis_jobs: dict = {}
_JOBS_MAX_AGE_SECONDS = 7200  # keep completed jobs for 2 hours


def _new_job_id() -> str:
    return secrets.token_urlsafe(16)


def _cleanup_jobs() -> None:
    cutoff = datetime.now(timezone.utc).timestamp() - _JOBS_MAX_AGE_SECONDS
    stale = [jid for jid, j in _analysis_jobs.items()
             if j.get("started_at", 0) < cutoff]
    for jid in stale:
        del _analysis_jobs[jid]

from auth import (
    authenticate_user, create_access_token, generate_api_key,
    get_current_user, get_password_hash, require_admin,
    validate_password_strength,
)
from config import settings
from database import (
    ApiKey, AuditLog, RetentionPolicy, SyslogEntry, User,
    get_db, get_stats, purge_old_entries, query_logs, query_logs_for_export,
    write_audit, SEVERITY_NAMES, FACILITY_NAMES,
)

router = APIRouter()


# ===================== Schemas =====================

class Token(BaseModel):
    access_token: str
    token_type: str


class LogEntryOut(BaseModel):
    id: int
    received_at: datetime
    source_ip: str
    facility: Optional[int]
    severity: Optional[int]
    severity_name: Optional[str]
    hostname: Optional[str]
    app_name: Optional[str]
    message: Optional[str]
    # normalized
    event_type: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    action: Optional[str]
    direction: Optional[str]
    rule_name: Optional[str]
    norm_user: Optional[str]
    domain: Optional[str]
    mac_address: Optional[str]

    class Config:
        from_attributes = True


class LogsPage(BaseModel):
    total: int
    offset: int
    limit: int
    entries: List[LogEntryOut]


class StatsOut(BaseModel):
    total_entries: int
    oldest_entry: Optional[str]
    newest_entry: Optional[str]
    by_severity: list
    top_sources: list


class RetentionIn(BaseModel):
    retention_days: int
    max_entries: int


class RetentionOut(RetentionIn):
    updated_at: datetime


class UserOut(BaseModel):
    id: int
    username: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: bool = False


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class ApiKeyOut(BaseModel):
    id: int
    label: str
    created_at: datetime
    last_used_at: Optional[datetime]
    is_active: bool
    read_only: bool

    class Config:
        from_attributes = True


class ApiKeyCreate(BaseModel):
    label: str
    read_only: bool = True


class ResetPassword(BaseModel):
    new_password: str


class AiAnalyzeBody(BaseModel):
    hours: int = 24
    focus: str = "security threats and anomalies"

    @field_validator("focus")
    @classmethod
    def cap_focus(cls, v: str) -> str:
        return v[:200]

    @field_validator("hours")
    @classmethod
    def cap_hours(cls, v: int) -> int:
        if v < 1: return 1
        if v > 720: return 720
        return v


class ApiKeyCreated(ApiKeyOut):
    raw_key: str  # Only returned once on creation


# ===================== First-run Setup =====================

class SetupInit(BaseModel):
    username: str
    password: str
    anthropic_api_key: str = ""


@router.get("/setup/status", tags=["setup"])
async def setup_status(db: Session = Depends(get_db)):
    """Returns whether the initial admin account has been created. Unauthenticated."""
    has_admin = db.query(User).filter_by(is_admin=True).first() is not None
    return {"setup_complete": has_admin}


@router.post("/setup/initialize", status_code=201, tags=["setup"])
async def setup_initialize(
    request: Request,
    body: SetupInit,
    db: Session = Depends(get_db),
):
    """Create the first admin account. Only works when no admin exists. Unauthenticated."""
    if db.query(User).filter_by(is_admin=True).first():
        raise HTTPException(status_code=409, detail="Setup already complete. Sign in to manage users.")
    if not body.username or not body.username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty.")
    err = validate_password_strength(body.password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    user = User(
        username=body.username.strip(),
        hashed_password=get_password_hash(body.password),
        is_active=True,
        is_admin=True,
    )
    db.add(user)
    if body.anthropic_api_key.strip():
        from database import set_service_setting
        set_service_setting("anthropic_api_key", body.anthropic_api_key.strip(), db)
    write_audit(db, body.username.strip(), "setup.initialize",
                "Initial setup: admin account created",
                request.client.host if request.client else "")
    db.commit()
    return {"message": "Setup complete. You can now sign in."}


# ===================== Auth =====================

@router.post("/auth/token", response_model=Token, tags=["auth"])
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Clear rate-limit counter on successful login
    from main import clear_login_attempts
    ip = request.client.host if request.client else "unknown"
    clear_login_attempts(ip)
    token_version = getattr(user, "token_version", 0)
    token = create_access_token({"sub": user.username, "ver": token_version})
    write_audit(db, user.username, "auth.login", f"Login from {ip}", ip)
    db.commit()
    return {"access_token": token, "token_type": "bearer"}


# ===================== Logs =====================

@router.get("/logs", response_model=LogsPage, tags=["logs"])
async def list_logs(
    source_ip: Optional[str] = Query(None),
    severity_max: Optional[int] = Query(None, ge=0, le=7),
    hostname: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    # normalized filters
    event_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    dst_port: Optional[int] = Query(None),
    protocol: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    entries, total = query_logs(
        db,
        source_ip=source_ip,
        severity_max=severity_max,
        hostname=hostname,
        search=search,
        since=since,
        until=until,
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        action=action,
        limit=limit,
        offset=offset,
    )
    return LogsPage(
        total=total,
        offset=offset,
        limit=limit,
        entries=[
            LogEntryOut(
                id=e.id,
                received_at=e.received_at,
                source_ip=e.source_ip or "",
                facility=e.facility,
                severity=e.severity,
                severity_name=SEVERITY_NAMES[e.severity] if e.severity is not None and e.severity < 8 else None,
                hostname=e.hostname,
                app_name=e.app_name,
                message=e.message,
                event_type=e.event_type,
                src_ip=e.src_ip,
                dst_ip=e.dst_ip,
                src_port=e.src_port,
                dst_port=e.dst_port,
                protocol=e.protocol,
                action=e.action,
                direction=e.direction,
                rule_name=e.rule_name,
                norm_user=e.norm_user,
                domain=e.domain,
                mac_address=e.mac_address,
            )
            for e in entries
        ],
    )


@router.get("/logs/{entry_id}", tags=["logs"])
async def get_log(
    entry_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    entry = db.query(SyslogEntry).filter_by(id=entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    import json as _json
    return {
        "id": entry.id,
        "received_at": entry.received_at,
        "source_ip": entry.source_ip,
        "facility": entry.facility,
        "severity": entry.severity,
        "severity_name": SEVERITY_NAMES[entry.severity] if entry.severity is not None and entry.severity < 8 else None,
        "hostname": entry.hostname,
        "app_name": entry.app_name,
        "proc_id": entry.proc_id,
        "msg_id": entry.msg_id,
        "message": entry.message,
        "raw": entry.raw,
        # normalized
        "event_type": entry.event_type,
        "src_ip": entry.src_ip,
        "dst_ip": entry.dst_ip,
        "src_port": entry.src_port,
        "dst_port": entry.dst_port,
        "protocol": entry.protocol,
        "action": entry.action,
        "direction": entry.direction,
        "interface_in": entry.interface_in,
        "interface_out": entry.interface_out,
        "mac_address": entry.mac_address,
        "rule_name": entry.rule_name,
        "user": entry.norm_user,
        "domain": entry.domain,
        "extra": _json.loads(entry.extra_json) if entry.extra_json else None,
    }


# ===================== Stats =====================

@router.get("/stats", response_model=StatsOut, tags=["stats"])
async def stats(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return get_stats(db)


# ===================== AI Analysis =====================

@router.post("/ai/analyze", tags=["ai"])
async def ai_analyze(
    body: AiAnalyzeBody,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    from ai_analysis import analyze_logs
    from database import get_service_setting

    _cleanup_jobs()

    since = datetime.now(timezone.utc) - timedelta(hours=body.hours)
    max_logs = int(get_service_setting("ai_analysis_max_logs", db=db) or settings.ai_analysis_max_logs)
    entries, _ = query_logs(db, since=since, limit=max_logs)
    if not entries:
        return {
            "job_id": None,
            "status": "done",
            "result": {"analysis": "No log entries found for the requested time window.", "log_count": 0},
        }

    job_id = _new_job_id()
    _analysis_jobs[job_id] = {
        "status": "running",
        "result": None,
        "started_at": datetime.now(timezone.utc).timestamp(),
        "username": current.username,
        "log_count": len(entries),
        "hours": body.hours,
    }

    async def _run():
        try:
            result = await analyze_logs(entries, focus=body.focus, hours=body.hours)
            _analysis_jobs[job_id]["status"] = "done"
            _analysis_jobs[job_id]["result"] = result
        except Exception as exc:
            _analysis_jobs[job_id]["status"] = "error"
            _analysis_jobs[job_id]["result"] = {"error": str(exc), "log_count": len(entries)}

    asyncio.create_task(_run())

    return {
        "job_id": job_id,
        "status": "running",
        "log_count": len(entries),
    }


@router.get("/ai/analyze/status/{job_id}", tags=["ai"])
async def ai_analyze_status(
    job_id: str,
    current: User = Depends(get_current_user),
):
    job = _analysis_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired.")
    if job.get("username") != current.username:
        raise HTTPException(status_code=403)
    elapsed = int(datetime.now(timezone.utc).timestamp() - job.get("started_at", 0))
    return {
        "job_id": job_id,
        "status": job["status"],
        "elapsed_seconds": elapsed,
        "log_count": job.get("log_count"),
        "hours": job.get("hours"),
        "result": job["result"] if job["status"] != "running" else None,
    }


@router.get("/ai/recommendations", tags=["ai"])
async def ai_quick_recommendations(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Quick 24-hour security scan — lightweight endpoint for Claude Projects."""
    from ai_analysis import analyze_logs
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    entries, _ = query_logs(db, severity_max=4, since=since, limit=200)
    if not entries:
        return {"analysis": "No high-severity events in the last 24 hours.", "log_count": 0}
    return await analyze_logs(entries, focus="security threats and anomalies", hours=24)


# ===================== AI History & Context =====================

class RecommendationUpdate(BaseModel):
    status: str       # open | implemented | working | investigating | dismissed
    user_notes: Optional[str] = None


@router.get("/ai/history", tags=["ai"])
async def get_ai_history(
    limit: int = Query(20, ge=1, le=100),
    analysis_id: int = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    from database import AIAnalysis, AIRecommendation
    q = db.query(AIAnalysis)
    if analysis_id is not None:
        q = q.filter(AIAnalysis.id == analysis_id)
    analyses = (
        q.order_by(AIAnalysis.analyzed_at.desc())
        .limit(limit)
        .all()
    )
    out = []
    for a in analyses:
        recs = db.query(AIRecommendation).filter_by(analysis_id=a.id).all()
        out.append({
            "id": a.id,
            "analyzed_at": a.analyzed_at,
            "focus": a.focus,
            "hours_covered": a.hours_covered,
            "log_count": a.log_count,
            "threat_level": a.threat_level,
            "summary": a.summary,
            "recommendations": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "detail": r.detail,
                    "recommendation": r.recommendation,
                    "status": r.status,
                    "user_notes": r.user_notes,
                    "updated_at": r.updated_at,
                }
                for r in recs
            ],
        })
    return out


@router.patch("/ai/recommendations/{rec_id}", tags=["ai"])
async def update_recommendation(
    rec_id: int,
    body: RecommendationUpdate,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    from database import AIRecommendation
    valid = {"open", "implemented", "working", "investigating", "dismissed"}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid))}")
    rec = db.query(AIRecommendation).filter_by(id=rec_id).first()
    if not rec:
        raise HTTPException(status_code=404)
    rec.status = body.status
    if body.user_notes is not None:
        rec.user_notes = body.user_notes
    rec.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": rec.id, "status": rec.status, "user_notes": rec.user_notes}


@router.get("/ai/network-context", tags=["ai"])
async def get_network_context(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from database import AINetworkContext
    ctx = db.query(AINetworkContext).filter_by(id=1).first()
    return {"content": ctx.content if ctx else "", "updated_at": ctx.updated_at if ctx else None}


@router.put("/ai/network-context", tags=["ai"])
async def update_network_context(
    body: dict,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    from database import AINetworkContext
    content = str(body.get("content", ""))[:4000]
    ctx = db.query(AINetworkContext).filter_by(id=1).first()
    if ctx:
        ctx.content = content
        ctx.updated_at = datetime.now(timezone.utc)
    else:
        db.add(AINetworkContext(id=1, content=content))
    db.commit()
    return {"message": "Network context saved."}


# ===================== Retention =====================

@router.get("/admin/retention", response_model=RetentionOut, tags=["admin"])
async def get_retention(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    policy = db.query(RetentionPolicy).first()
    return RetentionOut(
        retention_days=policy.retention_days,
        max_entries=policy.max_entries,
        updated_at=policy.updated_at,
    )


@router.put("/admin/retention", response_model=RetentionOut, tags=["admin"])
async def set_retention(
    request: Request,
    body: RetentionIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    policy = db.query(RetentionPolicy).first()
    policy.retention_days = body.retention_days
    policy.max_entries = body.max_entries
    policy.updated_at = datetime.now(timezone.utc)
    write_audit(db, admin.username, "retention.update",
                f"Retention set to {body.retention_days}d / {body.max_entries} entries",
                request.client.host if request.client else "")
    db.commit()
    return RetentionOut(retention_days=policy.retention_days, max_entries=policy.max_entries, updated_at=policy.updated_at)


@router.post("/admin/purge", tags=["admin"])
async def manual_purge(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    deleted = purge_old_entries(db)
    write_audit(db, admin.username, "logs.purge", f"Manual purge: removed {deleted} entries",
                request.client.host if request.client else "")
    db.commit()
    return {"deleted": deleted, "message": f"Purged {deleted} entries beyond retention window."}


# ===================== Users =====================

@router.get("/admin/users", response_model=List[UserOut], tags=["admin"])
async def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return db.query(User).all()


@router.post("/admin/users", response_model=UserOut, status_code=201, tags=["admin"])
async def create_user(
    request: Request,
    body: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    err = validate_password_strength(body.password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    if db.query(User).filter_by(username=body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=body.username, hashed_password=get_password_hash(body.password), is_admin=body.is_admin)
    db.add(user)
    write_audit(db, admin.username, "user.create",
                f"Created user '{body.username}' (admin={body.is_admin})",
                request.client.host if request.client else "")
    db.commit()
    db.refresh(user)
    return user


@router.delete("/admin/users/{user_id}", status_code=204, tags=["admin"])
async def delete_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == current.username:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    write_audit(db, current.username, "user.delete", f"Deleted user '{user.username}'",
                request.client.host if request.client else "")
    db.delete(user)
    db.commit()


@router.post("/admin/users/{user_id}/reset-password", tags=["admin"])
async def reset_user_password(
    request: Request,
    user_id: int,
    body: "ResetPassword",
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    err = validate_password_strength(body.new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    user.hashed_password = get_password_hash(body.new_password)
    user.token_version = (getattr(user, "token_version", 0) or 0) + 1
    write_audit(db, admin.username, "user.reset_password",
                f"Reset password for user '{user.username}'",
                request.client.host if request.client else "")
    db.commit()
    return {"message": f"Password reset for '{user.username}'. Their active sessions have been invalidated."}


@router.post("/auth/change-password", tags=["auth"])
async def change_password(
    body: PasswordChange,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    err = validate_password_strength(body.new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    user = db.query(User).filter_by(username=current.username).first()
    if not user:
        raise HTTPException(status_code=404)
    from auth import verify_password
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.hashed_password = get_password_hash(body.new_password)
    user.token_version = (getattr(user, "token_version", 0) or 0) + 1
    write_audit(db, current.username, "auth.password_change", "Password changed", "")
    db.commit()
    return {"message": "Password updated. Please sign in again."}


# ===================== API Keys =====================

@router.get("/admin/apikeys", response_model=List[ApiKeyOut], tags=["admin"])
async def list_api_keys(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return db.query(ApiKey).all()


@router.post("/admin/apikeys", response_model=ApiKeyCreated, status_code=201, tags=["admin"])
async def create_api_key(
    request: Request,
    body: ApiKeyCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    raw = generate_api_key()
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    record = ApiKey(key_hash=key_hash, label=body.label, read_only=body.read_only)
    db.add(record)
    write_audit(db, admin.username, "apikey.create", f"Created API key '{body.label}'",
                request.client.host if request.client else "")
    db.commit()
    db.refresh(record)
    return ApiKeyCreated(id=record.id, label=record.label, created_at=record.created_at,
                         last_used_at=record.last_used_at, is_active=record.is_active,
                         read_only=record.read_only, raw_key=raw)


@router.delete("/admin/apikeys/{key_id}", status_code=204, tags=["admin"])
async def revoke_api_key(
    request: Request,
    key_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    record = db.query(ApiKey).filter_by(id=key_id).first()
    if not record:
        raise HTTPException(status_code=404)
    write_audit(db, admin.username, "apikey.revoke", f"Revoked API key '{record.label}'",
                request.client.host if request.client else "")
    record.is_active = False
    db.commit()


# ===================== Service Info =====================

@router.get("/info", tags=["info"])
async def service_info(_: User = Depends(get_current_user)):
    from database import get_service_setting
    ai_provider = get_service_setting("ai_provider") or "anthropic"
    api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
    local_url = get_service_setting("ai_local_url") or ""
    ai_enabled = (ai_provider == "anthropic" and bool(api_key)) or \
                 (ai_provider == "local" and bool(local_url))
    return {
        "service": settings.service_display_name,
        "version": "1.0.0",
        "syslog_udp_port": settings.syslog_udp_port,
        "syslog_tcp_port": settings.syslog_tcp_port,
        "claude_model": get_service_setting("claude_model") or settings.claude_model,
        "ai_enabled": ai_enabled,
        "ai_provider": ai_provider,
    }


# ===================== Service Settings =====================

class ServiceSettingUpdate(BaseModel):
    value: str


@router.get("/admin/settings", tags=["admin"])
async def get_settings(_: User = Depends(require_admin)):
    from database import get_service_setting
    api_key = get_service_setting("anthropic_api_key")
    claude_model = get_service_setting("claude_model") or settings.claude_model
    return {
        "anthropic_api_key_set": bool(api_key),
        "anthropic_api_key_hint": "configured" if api_key else "not set",
        "claude_model": claude_model,
        "available_models": [
            {"id": "claude-sonnet-4-6",        "label": "Claude Sonnet 4.6  (recommended — best balance)"},
            {"id": "claude-sonnet-4-5",         "label": "Claude Sonnet 4.5  (previous Sonnet)"},
            {"id": "claude-opus-4-7",           "label": "Claude Opus 4.7    (most capable, higher cost)"},
            {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5   (fastest, lowest token cost)"},
        ],
        "ai_provider": get_service_setting("ai_provider") or "anthropic",
        "ai_local_url": get_service_setting("ai_local_url") or "",
        "ai_local_model": get_service_setting("ai_local_model") or "llama3.2",
    }


@router.put("/admin/settings/anthropic-key", tags=["admin"])
async def update_anthropic_key(
    request: Request,
    body: ServiceSettingUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import set_service_setting
    if not body.value.strip():
        raise HTTPException(status_code=400, detail="API key cannot be empty")
    set_service_setting("anthropic_api_key", body.value.strip(), db)
    write_audit(db, admin.username, "settings.anthropic_key", "Anthropic API key updated",
                request.client.host if request.client else "")
    db.commit()
    return {"message": "Anthropic API key updated and encrypted in database."}


@router.delete("/admin/settings/anthropic-key", tags=["admin"])
async def delete_anthropic_key(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import set_service_setting
    set_service_setting("anthropic_api_key", "", db)
    write_audit(db, admin.username, "settings.anthropic_key", "Anthropic API key removed",
                request.client.host if request.client else "")
    db.commit()
    return {"message": "Anthropic API key removed."}


@router.put("/admin/settings/claude-model", tags=["admin"])
async def update_claude_model(
    request: Request,
    body: ServiceSettingUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import set_service_setting
    set_service_setting("claude_model", body.value.strip(), db)
    write_audit(db, admin.username, "settings.claude_model", f"Claude model set to {body.value.strip()}",
                request.client.host if request.client else "")
    db.commit()
    return {"message": f"Claude model updated to {body.value.strip()}"}


@router.post("/admin/settings/test-anthropic-key", tags=["admin"])
async def test_anthropic_key(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Verify the stored Anthropic API key is valid by making a minimal API call."""
    import logging as _logging
    from database import get_service_setting
    import anthropic as _anthropic
    _log = _logging.getLogger("routes")
    api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
    if not api_key:
        raise HTTPException(status_code=400, detail="No Anthropic API key configured.")
    write_audit(db, admin.username, "settings.test_anthropic_key", "Tested Anthropic API key",
                request.client.host if request.client else "")
    db.commit()
    try:
        client = _anthropic.AsyncAnthropic(api_key=api_key)
        await client.messages.create(
            model=get_service_setting("claude_model") or settings.claude_model,
            max_tokens=10,
            messages=[{"role": "user", "content": "ping"}],
            timeout=15.0,
        )
        return {"status": "ok", "message": "API key is valid and working."}
    except _anthropic.AuthenticationError:
        raise HTTPException(status_code=400, detail="API key is invalid or expired.")
    except Exception as exc:
        _log.error("Anthropic connection test failed: %s", exc)
        raise HTTPException(status_code=400, detail="Connection failed. Check service logs for details.")


# ===================== Local LLM Settings =====================

class LocalLLMSettings(BaseModel):
    ai_provider: str          # "anthropic" | "local"
    ai_local_url: str = ""    # e.g. http://localhost:11434
    ai_local_model: str = ""  # e.g. llama3.2


@router.put("/admin/settings/local-llm", tags=["admin"])
async def update_local_llm(
    request: Request,
    body: LocalLLMSettings,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import set_service_setting
    provider = body.ai_provider.strip().lower()
    if provider not in ("anthropic", "local"):
        raise HTTPException(status_code=400, detail="ai_provider must be 'anthropic' or 'local'")
    set_service_setting("ai_provider", provider, db)
    if body.ai_local_url.strip():
        set_service_setting("ai_local_url", body.ai_local_url.strip().rstrip("/"), db)
    if body.ai_local_model.strip():
        set_service_setting("ai_local_model", body.ai_local_model.strip(), db)
    write_audit(db, admin.username, "settings.ai_provider", f"AI provider set to {provider}",
                request.client.host if request.client else "")
    db.commit()
    return {"message": f"AI provider updated to {provider}"}


@router.get("/admin/settings/local-llm/models", tags=["admin"])
async def list_local_models(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Fetch the model list from a running Ollama/LM Studio instance."""
    import httpx as _httpx
    from database import get_service_setting
    base_url = get_service_setting("ai_local_url") or ""
    if not base_url:
        raise HTTPException(status_code=400, detail="Local LLM URL not configured.")
    try:
        async with _httpx.AsyncClient(timeout=8.0) as client:
            # Try Ollama's native tags endpoint first
            try:
                r = await client.get(f"{base_url}/api/tags")
                if r.status_code == 200:
                    data = r.json()
                    models = [m["name"] for m in data.get("models", [])]
                    return {"models": models, "source": "ollama"}
            except Exception:
                pass
            # Fall back to OpenAI-compatible /v1/models
            r = await client.get(f"{base_url}/v1/models")
            r.raise_for_status()
            data = r.json()
            models = [m["id"] for m in data.get("data", [])]
            return {"models": models, "source": "openai_compat"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not reach {base_url}: {exc}")


@router.post("/admin/settings/test-local-llm", tags=["admin"])
async def test_local_llm(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Send a minimal chat completion to verify the local LLM is reachable and working."""
    import httpx as _httpx
    from database import get_service_setting
    base_url = get_service_setting("ai_local_url") or ""
    model = get_service_setting("ai_local_model") or "llama3.2"
    if not base_url:
        raise HTTPException(status_code=400, detail="Local LLM URL not configured.")
    write_audit(db, admin.username, "settings.test_local_llm", "Tested local LLM connection",
                request.client.host if request.client else "")
    db.commit()
    try:
        async with _httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{base_url}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "Reply with one word: OK"}],
                    "max_tokens": 10,
                },
            )
            r.raise_for_status()
            reply = r.json()["choices"][0]["message"]["content"]
            return {"status": "ok", "message": f"Connected to {base_url} — model '{model}' responded: {reply.strip()[:80]}"}
    except _httpx.ConnectError:
        raise HTTPException(status_code=400, detail=f"Connection refused at {base_url}. Is the local LLM server running?")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Test failed: {exc}")


# ===================== Web Update =====================

@router.get("/admin/update/info", tags=["admin"])
async def get_update_info(_: User = Depends(require_admin)):
    """Return current git version info. Used to show version in the web console."""
    import shutil as _shutil
    import subprocess as _sp
    from pathlib import Path as _Path
    install_dir = _Path(__file__).parent.parent
    info: dict = {
        "git_available": bool(_shutil.which("git")),
        "is_git_repo": (install_dir / ".git").exists(),
        "current_commit": None,
        "commit_date": None,
        "branch": None,
    }
    if not info["git_available"] or not info["is_git_repo"]:
        return info
    def _git(*args):
        return _sp.check_output(["git", *args], cwd=str(install_dir),
                                 stderr=_sp.DEVNULL, timeout=8).decode().strip()
    try:
        info["current_commit"] = _git("log", "-1", "--format=%h")
        info["commit_date"]    = _git("log", "-1", "--format=%ci")
        info["branch"]         = _git("rev-parse", "--abbrev-ref", "HEAD")
    except Exception:
        pass
    return info


@router.post("/admin/update", tags=["admin"])
async def trigger_update(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Pull latest code from GitHub, reinstall dependencies, then restart.
    Runs git pull + pip install in a background thread so the HTTP response
    is delivered before the service restarts.
    """
    import asyncio as _asyncio
    import logging as _logging
    import os as _os
    import shutil as _shutil
    import signal as _signal
    import subprocess as _sp
    from pathlib import Path as _Path

    _log = _logging.getLogger("update")
    install_dir = _Path(__file__).parent.parent

    if not _shutil.which("git"):
        raise HTTPException(status_code=400, detail="Git is not installed on this system.")
    if not (install_dir / ".git").exists():
        raise HTTPException(status_code=400,
            detail="Install directory is not a git repo. Run option 1 (Install) via install.sh first.")

    write_audit(db, admin.username, "admin.update",
                "Web console update triggered", request.client.host if request.client else "")
    db.commit()

    async def _do_update():
        await _asyncio.sleep(0.8)   # let the HTTP response reach the browser
        pip = str(install_dir / ".venv" / "bin" / "pip")
        req = str(install_dir / "requirements-linux.txt")
        if not _Path(req).exists():
            req = str(install_dir / "requirements.txt")
        try:
            _log.info("Update: running git pull")
            await _asyncio.to_thread(_sp.run,
                ["git", "pull", "origin", "main"],
                cwd=str(install_dir), capture_output=True, timeout=120)
            _log.info("Update: running pip install")
            await _asyncio.to_thread(_sp.run,
                [pip, "install", "-r", req,
                 "--quiet", "--no-cache-dir", "--timeout", "120"],
                capture_output=True, timeout=600)
        except Exception as exc:
            _log.error("Update failed during git/pip: %s", exc)
        # Restart: try sudo systemctl first, fall back to SIGTERM so systemd restarts
        _log.info("Update: restarting service")
        r = await _asyncio.to_thread(_sp.run,
            ["sudo", "systemctl", "restart", "syslog-siem"],
            capture_output=True, timeout=15)
        if r.returncode != 0:
            _log.info("sudo systemctl failed — sending SIGTERM for systemd auto-restart")
            _os.kill(_os.getpid(), _signal.SIGTERM)

    _asyncio.create_task(_do_update())
    return {
        "status": "started",
        "message": "Update in progress. The service will restart shortly.",
        "restart_wait_seconds": 35,
    }


# ===================== Audit Log =====================

@router.get("/admin/audit", tags=["admin"])
async def get_audit_log(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    if username:
        q = q.filter(AuditLog.username == username)
    total = q.count()
    entries = q.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "username": e.username,
                "action": e.action,
                "detail": e.detail,
                "ip_address": e.ip_address,
            }
            for e in entries
        ],
    }


# ===================== CSV Export =====================

@router.get("/logs/export", tags=["logs"])
async def export_logs_csv(
    source_ip: Optional[str] = Query(None),
    severity_max: Optional[int] = Query(None, ge=0, le=7),
    hostname: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    event_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    dst_port: Optional[int] = Query(None),
    protocol: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    max_rows: int = Query(50000, ge=1, le=100000),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rows = query_logs_for_export(
        db, max_rows=max_rows,
        source_ip=source_ip, severity_max=severity_max, hostname=hostname,
        search=search, since=since, until=until, event_type=event_type,
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        protocol=protocol, action=action,
    )

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "received_at", "source_ip", "severity", "severity_name",
            "hostname", "app_name", "event_type", "action", "src_ip", "dst_ip",
            "dst_port", "protocol", "rule_name", "message",
        ])
        yield buf.getvalue()
        buf.truncate(0); buf.seek(0)
        for e in rows:
            sev_name = SEVERITY_NAMES[e.severity] if e.severity is not None and e.severity < 8 else ""
            writer.writerow([
                e.id, e.received_at, e.source_ip, e.severity, sev_name,
                e.hostname, e.app_name, e.event_type, e.action,
                e.src_ip, e.dst_ip, e.dst_port, e.protocol, e.rule_name,
                e.message,
            ])
            yield buf.getvalue()
            buf.truncate(0); buf.seek(0)

    filename = f"syslog_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ===================== Service Configuration =====================

class ServiceConfigUpdate(BaseModel):
    allowed_syslog_sources: Optional[str] = None
    login_max_attempts: Optional[int] = None
    login_lockout_seconds: Optional[int] = None
    access_token_expire_minutes: Optional[int] = None
    ai_analysis_max_logs: Optional[int] = None


@router.get("/admin/settings/service", tags=["admin"])
async def get_service_config(_: User = Depends(require_admin)):
    from database import get_service_setting
    return {
        "allowed_syslog_sources": get_service_setting("allowed_syslog_sources"),
        "login_max_attempts": int(get_service_setting("login_max_attempts") or settings.login_max_attempts),
        "login_lockout_seconds": int(get_service_setting("login_lockout_seconds") or settings.login_lockout_seconds),
        "access_token_expire_minutes": int(get_service_setting("access_token_expire_minutes") or settings.access_token_expire_minutes),
        "ai_analysis_max_logs": int(get_service_setting("ai_analysis_max_logs") or settings.ai_analysis_max_logs),
    }


@router.put("/admin/settings/service", tags=["admin"])
async def update_service_config(
    request: Request,
    body: ServiceConfigUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import set_service_setting
    changed = []
    if body.allowed_syslog_sources is not None:
        set_service_setting("allowed_syslog_sources", body.allowed_syslog_sources, db)
        changed.append("allowed_syslog_sources")
    if body.login_max_attempts is not None:
        set_service_setting("login_max_attempts", str(body.login_max_attempts), db)
        changed.append("login_max_attempts")
    if body.login_lockout_seconds is not None:
        set_service_setting("login_lockout_seconds", str(body.login_lockout_seconds), db)
        changed.append("login_lockout_seconds")
    if body.access_token_expire_minutes is not None:
        set_service_setting("access_token_expire_minutes", str(body.access_token_expire_minutes), db)
        changed.append("access_token_expire_minutes")
    if body.ai_analysis_max_logs is not None:
        set_service_setting("ai_analysis_max_logs", str(body.ai_analysis_max_logs), db)
        changed.append("ai_analysis_max_logs")
    write_audit(db, admin.username, "settings.service",
                f"Service config updated: {', '.join(changed)}",
                request.client.host if request.client else "")
    db.commit()
    return {"message": "Service configuration saved."}


# ===================== Investigation =====================

@router.get("/investigation/{ip}", tags=["investigation"])
async def investigate_ip(
    ip: str,
    hours: int = Query(168, ge=1, le=8760),  # default 7 days
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """All activity for a specific IP — timeline, event types, rules triggered, sample logs."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(SyslogEntry).filter(
        (SyslogEntry.source_ip == ip) | (SyslogEntry.src_ip == ip) | (SyslogEntry.dst_ip == ip),
        SyslogEntry.received_at >= since,
    )
    total = q.count()
    entries = q.order_by(SyslogEntry.received_at.desc()).limit(500).all()

    # Event type breakdown
    from sqlalchemy import func as sqlfunc
    type_counts = (
        db.query(SyslogEntry.event_type, sqlfunc.count(SyslogEntry.id))
        .filter(
            (SyslogEntry.source_ip == ip) | (SyslogEntry.src_ip == ip) | (SyslogEntry.dst_ip == ip),
            SyslogEntry.received_at >= since,
        )
        .group_by(SyslogEntry.event_type)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .all()
    )

    # Rules triggered
    rule_counts = (
        db.query(SyslogEntry.rule_name, sqlfunc.count(SyslogEntry.id))
        .filter(
            (SyslogEntry.source_ip == ip) | (SyslogEntry.src_ip == ip),
            SyslogEntry.received_at >= since,
            SyslogEntry.rule_name.isnot(None),
        )
        .group_by(SyslogEntry.rule_name)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .limit(10)
        .all()
    )

    # Ports targeted
    port_counts = (
        db.query(SyslogEntry.dst_port, sqlfunc.count(SyslogEntry.id))
        .filter(
            SyslogEntry.src_ip == ip,
            SyslogEntry.received_at >= since,
            SyslogEntry.dst_port.isnot(None),
        )
        .group_by(SyslogEntry.dst_port)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .limit(15)
        .all()
    )

    # First / last seen
    first_seen = db.query(sqlfunc.min(SyslogEntry.received_at)).filter(
        (SyslogEntry.source_ip == ip) | (SyslogEntry.src_ip == ip)
    ).scalar()
    last_seen = db.query(sqlfunc.max(SyslogEntry.received_at)).filter(
        (SyslogEntry.source_ip == ip) | (SyslogEntry.src_ip == ip)
    ).scalar()

    return {
        "ip": ip,
        "hours": hours,
        "total_events": total,
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "event_types": [{"type": t or "unknown", "count": c} for t, c in type_counts],
        "rules_triggered": [{"rule": r or "unknown", "count": c} for r, c in rule_counts],
        "ports_targeted": [{"port": p, "count": c} for p, c in port_counts],
        "recent_events": [
            {
                "id": e.id,
                "received_at": e.received_at,
                "event_type": e.event_type,
                "action": e.action,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "rule_name": e.rule_name,
                "message": (e.message or "")[:200],
                "severity": e.severity,
            }
            for e in entries[:100]
        ],
    }


@router.get("/investigation/{ip}/enrich", tags=["investigation"])
async def enrich_ip_route(
    ip: str,
    _: User = Depends(get_current_user),
):
    """Fetch AbuseIPDB reputation score and GeoIP data for an IP."""
    from enrichment import enrich_ip
    return await enrich_ip(ip)


# ===================== Analysis =====================

@router.get("/analysis/timeline", tags=["analysis"])
async def get_timeline(
    hours: int = Query(24, ge=1, le=168),
    event_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Hourly event counts for the dashboard sparkline."""
    from sqlalchemy import func as sqlfunc, text as sqtext
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(SyslogEntry).filter(SyslogEntry.received_at >= since)
    if event_type:
        q = q.filter(SyslogEntry.event_type == event_type)

    # Build hourly buckets
    all_entries = q.with_entities(SyslogEntry.received_at, SyslogEntry.action).all()
    buckets: dict[str, dict] = {}
    for ts, action in all_entries:
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        hour_key = ts.strftime("%Y-%m-%dT%H:00")
        if hour_key not in buckets:
            buckets[hour_key] = {"total": 0, "blocks": 0, "allows": 0}
        buckets[hour_key]["total"] += 1
        if action == "BLOCK":
            buckets[hour_key]["blocks"] += 1
        elif action == "ALLOW":
            buckets[hour_key]["allows"] += 1

    # Fill missing hours with zeros
    result = []
    for h in range(hours - 1, -1, -1):
        ts = datetime.now(timezone.utc) - timedelta(hours=h)
        key = ts.strftime("%Y-%m-%dT%H:00")
        b = buckets.get(key, {"total": 0, "blocks": 0, "allows": 0})
        result.append({"hour": key, **b})

    return {"hours": hours, "buckets": result}


@router.get("/analysis/rule-hits", tags=["analysis"])
async def get_rule_hits(
    hours: int = Query(168, ge=1, le=8760),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Which firewall rules have fired most, with top source IPs per rule."""
    from sqlalchemy import func as sqlfunc
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rule_counts = (
        db.query(SyslogEntry.rule_name, SyslogEntry.action, sqlfunc.count(SyslogEntry.id))
        .filter(
            SyslogEntry.received_at >= since,
            SyslogEntry.rule_name.isnot(None),
        )
        .group_by(SyslogEntry.rule_name, SyslogEntry.action)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .limit(limit)
        .all()
    )

    results = []
    for rule, action, count in rule_counts:
        top_sources = (
            db.query(SyslogEntry.src_ip, sqlfunc.count(SyslogEntry.id))
            .filter(
                SyslogEntry.received_at >= since,
                SyslogEntry.rule_name == rule,
                SyslogEntry.src_ip.isnot(None),
            )
            .group_by(SyslogEntry.src_ip)
            .order_by(sqlfunc.count(SyslogEntry.id).desc())
            .limit(5)
            .all()
        )
        results.append({
            "rule": rule,
            "action": action,
            "count": count,
            "top_sources": [{"ip": ip, "count": c} for ip, c in top_sources],
        })
    return {"hours": hours, "rules": results}


@router.get("/analysis/traffic-matrix", tags=["analysis"])
async def get_traffic_matrix(
    hours: int = Query(24, ge=1, le=168),
    top_n: int = Query(15, ge=5, le=50),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Top destination ports × source subnets — for identifying unexpected traffic patterns."""
    from sqlalchemy import func as sqlfunc
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    port_counts = (
        db.query(SyslogEntry.dst_port, SyslogEntry.protocol, sqlfunc.count(SyslogEntry.id))
        .filter(
            SyslogEntry.received_at >= since,
            SyslogEntry.dst_port.isnot(None),
        )
        .group_by(SyslogEntry.dst_port, SyslogEntry.protocol)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .limit(top_n)
        .all()
    )

    event_type_counts = (
        db.query(SyslogEntry.event_type, SyslogEntry.action, sqlfunc.count(SyslogEntry.id))
        .filter(SyslogEntry.received_at >= since)
        .group_by(SyslogEntry.event_type, SyslogEntry.action)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .all()
    )

    src_counts = (
        db.query(SyslogEntry.src_ip, sqlfunc.count(SyslogEntry.id))
        .filter(SyslogEntry.received_at >= since, SyslogEntry.src_ip.isnot(None))
        .group_by(SyslogEntry.src_ip)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .limit(top_n)
        .all()
    )

    return {
        "hours": hours,
        "top_ports": [{"port": p, "protocol": pr or "", "count": c} for p, pr, c in port_counts],
        "event_action_matrix": [
            {"event_type": et or "unknown", "action": a or "", "count": c}
            for et, a, c in event_type_counts
        ],
        "top_sources": [{"ip": ip, "count": c} for ip, c in src_counts],
    }


@router.get("/analysis/network-graph", tags=["analysis"])
async def get_network_graph(
    hours: int = Query(168, ge=1, le=876000),
    limit: int = Query(500, ge=10, le=2000),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Source → destination traffic pairs for the network graph visualisation.
    Returns nodes (unique IPs) and edges (src/dst pairs) with event counts
    and last-seen timestamps for the pulsation animation.
    """
    from sqlalchemy import func as sqlfunc
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    pairs = (
        db.query(
            SyslogEntry.src_ip,
            SyslogEntry.dst_ip,
            sqlfunc.count(SyslogEntry.id).label("count"),
            sqlfunc.max(SyslogEntry.received_at).label("last_seen"),
        )
        .filter(
            SyslogEntry.received_at >= since,
            SyslogEntry.src_ip.isnot(None),
            SyslogEntry.dst_ip.isnot(None),
        )
        .group_by(SyslogEntry.src_ip, SyslogEntry.dst_ip)
        .order_by(sqlfunc.count(SyslogEntry.id).desc())
        .limit(limit)
        .all()
    )

    def subnet24(ip: str) -> str:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else ip

    def is_private(ip: str) -> bool:
        p = ip.split(".")
        if len(p) != 4:
            return False
        try:
            o = [int(x) for x in p]
            return (o[0] == 10 or
                    (o[0] == 172 and 16 <= o[1] <= 31) or
                    (o[0] == 192 and o[1] == 168) or
                    o[0] == 127)
        except ValueError:
            return False

    nodes: dict[str, dict] = {}
    edges = []

    for src_ip, dst_ip, count, last_seen in pairs:
        for ip in (src_ip, dst_ip):
            if ip not in nodes:
                nodes[ip] = {
                    "ip": ip,
                    "subnet": subnet24(ip),
                    "private": is_private(ip),
                    "events": 0,
                }
            nodes[ip]["events"] += count

        edges.append({
            "src": src_ip,
            "dst": dst_ip,
            "count": count,
            "last_seen": last_seen.isoformat() if last_seen else None,
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "hours": hours,
    }


@router.post("/analysis/simulate-rule", tags=["analysis"])
async def simulate_rule(
    src_cidr: Optional[str] = Body(None, embed=True),
    dst_cidr: Optional[str] = Body(None, embed=True),
    dst_port: Optional[int] = Body(None, embed=True),
    protocol: Optional[str] = Body(None, embed=True),
    action_filter: Optional[str] = Body(None, embed=True),
    hours: int = Body(168, embed=True, ge=1, le=8760),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Test a hypothetical firewall rule against historical logs — shows how many events it would match."""
    import ipaddress as _iplib
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(SyslogEntry).filter(SyslogEntry.received_at >= since)

    if dst_port:
        q = q.filter(SyslogEntry.dst_port == dst_port)
    if protocol:
        q = q.filter(SyslogEntry.protocol.ilike(protocol))
    if action_filter:
        q = q.filter(SyslogEntry.action == action_filter.upper())

    all_entries = q.with_entities(
        SyslogEntry.id, SyslogEntry.src_ip, SyslogEntry.dst_ip,
        SyslogEntry.dst_port, SyslogEntry.protocol, SyslogEntry.action,
        SyslogEntry.received_at, SyslogEntry.rule_name, SyslogEntry.event_type,
    ).all()

    # Filter by CIDR in Python (SQLite has no native CIDR matching)
    matched = []
    src_net = dst_net = None
    try:
        if src_cidr:
            src_net = _iplib.ip_network(src_cidr, strict=False)
        if dst_cidr:
            dst_net = _iplib.ip_network(dst_cidr, strict=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {e}")

    for e in all_entries:
        try:
            if src_net and e.src_ip:
                if _iplib.ip_address(e.src_ip) not in src_net:
                    continue
            if dst_net and e.dst_ip:
                if _iplib.ip_address(e.dst_ip) not in dst_net:
                    continue
        except ValueError:
            continue
        matched.append(e)

    sample = matched[:20]
    return {
        "matched_count": len(matched),
        "hours": hours,
        "rule": {
            "src_cidr": src_cidr,
            "dst_cidr": dst_cidr,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action_filter,
        },
        "sample_events": [
            {
                "id": e.id,
                "received_at": e.received_at,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "action": e.action,
                "event_type": e.event_type,
                "rule_name": e.rule_name,
            }
            for e in sample
        ],
    }


@router.post("/analysis/policy-gaps", tags=["analysis"])
async def analyze_policy_gaps(
    hours: int = Body(24, embed=True, ge=1, le=168),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """AI analysis of ALLOWED traffic to find unexpected or suspicious connections."""
    from ai_analysis import analyze_logs
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    entries, _ = query_logs(db, since=since, action="ALLOW", limit=300)
    if not entries:
        return {"analysis": "No ALLOW events found in the requested window.", "log_count": 0}
    return await analyze_logs(
        entries,
        focus="identify unexpected, suspicious, or risky ALLOWED connections that should potentially be blocked",
        hours=hours,
    )


# ── Webhook SSRF guard ───────────────────────────────────────────────────────

def _validate_webhook_url(url: str) -> None:
    """Raise 400 if the URL scheme is wrong or resolves to a private/loopback address."""
    import ipaddress as _iplib
    import socket as _socket
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Webhook URL must use http or https.")
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="Invalid webhook URL.")
    try:
        addr = _socket.getaddrinfo(host, None)[0][4][0]
        ip_obj = _iplib.ip_address(addr)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise HTTPException(
                status_code=400,
                detail="Webhook URL cannot target private or loopback addresses.",
            )
    except HTTPException:
        raise
    except Exception:
        pass  # DNS failure — let the actual send attempt surface the error


# ===================== Alert Rules =====================

class AlertRuleCreate(BaseModel):
    name: str
    condition_type: str
    condition_params: Optional[str] = "{}"
    window_minutes: int = 5
    threshold: int = 1
    cooldown_minutes: int = 60
    notify_webhook: Optional[str] = None
    notify_email: Optional[str] = None


class AlertRuleOut(AlertRuleCreate):
    id: int
    enabled: bool
    last_fired_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/admin/alerts/rules", response_model=List[AlertRuleOut], tags=["alerts"])
async def list_alert_rules(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    from database import AlertRule
    return db.query(AlertRule).order_by(AlertRule.created_at.desc()).all()


@router.post("/admin/alerts/rules", response_model=AlertRuleOut, status_code=201, tags=["alerts"])
async def create_alert_rule(
    request: Request,
    body: AlertRuleCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import AlertRule
    if body.notify_webhook:
        _validate_webhook_url(body.notify_webhook)
    rule = AlertRule(**body.model_dump())
    db.add(rule)
    write_audit(db, admin.username, "alert.create", f"Created alert rule '{body.name}'",
                request.client.host if request.client else "")
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/admin/alerts/rules/{rule_id}", response_model=AlertRuleOut, tags=["alerts"])
async def update_alert_rule(
    request: Request,
    rule_id: int,
    body: AlertRuleCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import AlertRule
    rule = db.query(AlertRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=404)
    if body.notify_webhook:
        _validate_webhook_url(body.notify_webhook)
    for k, v in body.model_dump().items():
        setattr(rule, k, v)
    write_audit(db, admin.username, "alert.update", f"Updated alert rule '{body.name}'",
                request.client.host if request.client else "")
    db.commit()
    return rule


@router.patch("/admin/alerts/rules/{rule_id}/toggle", tags=["alerts"])
async def toggle_alert_rule(
    request: Request,
    rule_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import AlertRule
    rule = db.query(AlertRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=404)
    rule.enabled = not rule.enabled
    write_audit(db, admin.username, "alert.toggle",
                f"Alert rule '{rule.name}' {'enabled' if rule.enabled else 'disabled'}",
                request.client.host if request.client else "")
    db.commit()
    return {"enabled": rule.enabled}


@router.delete("/admin/alerts/rules/{rule_id}", status_code=204, tags=["alerts"])
async def delete_alert_rule(
    request: Request,
    rule_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import AlertRule
    rule = db.query(AlertRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=404)
    write_audit(db, admin.username, "alert.delete", f"Deleted alert rule '{rule.name}'",
                request.client.host if request.client else "")
    db.delete(rule)
    db.commit()


@router.get("/admin/alerts/events", tags=["alerts"])
async def get_alert_events(
    limit: int = Query(100, ge=1, le=500),
    unacked_only: bool = Query(False),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    from database import AlertEvent
    q = db.query(AlertEvent)
    if unacked_only:
        q = q.filter_by(acknowledged=False)
    events = q.order_by(AlertEvent.fired_at.desc()).limit(limit).all()
    return [
        {
            "id": e.id, "rule_id": e.rule_id, "rule_name": e.rule_name,
            "fired_at": e.fired_at, "detail": e.detail, "acknowledged": e.acknowledged,
        }
        for e in events
    ]


@router.post("/admin/alerts/events/{event_id}/acknowledge", tags=["alerts"])
async def acknowledge_alert(
    event_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    from database import AlertEvent
    event = db.query(AlertEvent).filter_by(id=event_id).first()
    if not event:
        raise HTTPException(status_code=404)
    event.acknowledged = True
    db.commit()
    return {"acknowledged": True}


# ===================== Notifications / Digest =====================

@router.post("/admin/alerts/test-webhook", tags=["alerts"])
async def test_webhook(url: str = Body(embed=True), _: User = Depends(require_admin)):
    import httpx as _httpx
    _validate_webhook_url(url)
    try:
        async with _httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json={"test": True, "source": "SIEM Console"})
            return {"status": r.status_code, "ok": r.is_success}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/admin/digest/send", tags=["alerts"])
async def trigger_digest(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from alert_engine import send_daily_digest
    from database import get_service_setting
    to_email = get_service_setting("digest_email", db=db)
    if not to_email:
        raise HTTPException(status_code=400, detail="No digest email configured. Add it in Service Settings.")
    write_audit(db, admin.username, "digest.send", f"Manual digest triggered to {to_email}",
                request.client.host if request.client else "")
    db.commit()
    result = await send_daily_digest(to_email)
    return result


# ===================== Service Settings (SMTP + enrichment keys) =====================

@router.get("/admin/settings/notifications", tags=["admin"])
async def get_notification_settings(_: User = Depends(require_admin)):
    from database import get_service_setting
    return {
        "smtp_host": get_service_setting("smtp_host"),
        "smtp_port": get_service_setting("smtp_port") or "587",
        "smtp_user": get_service_setting("smtp_user"),
        "smtp_from": get_service_setting("smtp_from"),
        "smtp_password_set": bool(get_service_setting("smtp_password")),
        "digest_email": get_service_setting("digest_email"),
        "abuseipdb_key_set": bool(get_service_setting("abuseipdb_api_key")),
    }


@router.put("/admin/settings/notifications", tags=["admin"])
async def update_notification_settings(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from database import set_service_setting
    allowed = ["smtp_host", "smtp_port", "smtp_user", "smtp_from",
               "smtp_password", "digest_email", "abuseipdb_api_key"]
    for key in allowed:
        if key in body:
            set_service_setting(key, str(body[key]), db)
    write_audit(db, admin.username, "settings.notifications", "Notification settings updated",
                request.client.host if request.client else "")
    db.commit()
    return {"message": "Notification settings saved."}
