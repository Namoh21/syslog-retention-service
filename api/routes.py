"""
All REST API routes for the syslog retention service.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Optional

import csv
import io

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

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
    _: User = Depends(get_current_user),
):
    from ai_analysis import analyze_logs
    since = datetime.now(timezone.utc) - timedelta(hours=body.hours)
    entries, _ = query_logs(db, since=since, limit=settings.ai_analysis_max_logs)
    if not entries:
        return {"analysis": "No log entries found for the requested time window.", "log_count": 0}
    result = await analyze_logs(entries, focus=body.focus, hours=body.hours)
    return result


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
    api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
    claude_model = get_service_setting("claude_model") or settings.claude_model
    return {
        "service": settings.service_display_name,
        "version": "1.0.0",
        "syslog_udp_port": settings.syslog_udp_port,
        "syslog_tcp_port": settings.syslog_tcp_port,
        "claude_model": claude_model,
        "ai_enabled": bool(api_key),
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
        "anthropic_api_key_hint": f"...{api_key[-6:]}" if len(api_key) > 6 else ("set" if api_key else "not set"),
        "claude_model": claude_model,
        "available_models": [
            "claude-sonnet-4-6",
            "claude-opus-4-7",
            "claude-haiku-4-5-20251001",
        ],
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
async def test_anthropic_key(_: User = Depends(require_admin)):
    """Verify the stored Anthropic API key is valid by making a minimal API call."""
    from database import get_service_setting
    import anthropic as _anthropic
    api_key = get_service_setting("anthropic_api_key") or settings.anthropic_api_key
    if not api_key:
        raise HTTPException(status_code=400, detail="No Anthropic API key configured.")
    try:
        client = _anthropic.Anthropic(api_key=api_key)
        client.messages.create(
            model=get_service_setting("claude_model") or settings.claude_model,
            max_tokens=10,
            messages=[{"role": "user", "content": "ping"}],
        )
        return {"status": "ok", "message": "API key is valid and working."}
    except _anthropic.AuthenticationError:
        raise HTTPException(status_code=400, detail="API key is invalid or expired.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Connection failed: {exc}")


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
