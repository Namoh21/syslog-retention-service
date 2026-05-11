"""
All REST API routes for the syslog retention service.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import (
    authenticate_user, create_access_token, generate_api_key,
    get_current_user, get_password_hash, require_admin,
)
from config import settings
from database import (
    ApiKey, RetentionPolicy, SyslogEntry, User,
    get_db, get_stats, purge_old_entries, query_logs,
    SEVERITY_NAMES, FACILITY_NAMES,
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


class ApiKeyCreated(ApiKeyOut):
    raw_key: str  # Only returned once on creation


# ===================== Auth =====================

@router.post("/auth/token", response_model=Token, tags=["auth"])
async def login(
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
    token = create_access_token({"sub": user.username})
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
    hours: int = Body(24, embed=True, ge=1, le=720),
    focus: str = Body("security", embed=True),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    from ai_analysis import analyze_logs
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    entries, _ = query_logs(db, since=since, limit=settings.ai_analysis_max_logs)
    if not entries:
        return {"analysis": "No log entries found for the requested time window.", "log_count": 0}
    result = await analyze_logs(entries, focus=focus, hours=hours)
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
    body: RetentionIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    policy = db.query(RetentionPolicy).first()
    policy.retention_days = body.retention_days
    policy.max_entries = body.max_entries
    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RetentionOut(
        retention_days=policy.retention_days,
        max_entries=policy.max_entries,
        updated_at=policy.updated_at,
    )


@router.post("/admin/purge", tags=["admin"])
async def manual_purge(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    deleted = purge_old_entries(db)
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
    body: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    if db.query(User).filter_by(username=body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(
        username=body.username,
        hashed_password=get_password_hash(body.password),
        is_admin=body.is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/admin/users/{user_id}", status_code=204, tags=["admin"])
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == current.username:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    db.delete(user)
    db.commit()


@router.post("/auth/change-password", tags=["auth"])
async def change_password(
    body: PasswordChange,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    user = db.query(User).filter_by(username=current.username).first()
    if not user:
        raise HTTPException(status_code=404)
    from auth import verify_password
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.hashed_password = get_password_hash(body.new_password)
    db.commit()
    return {"message": "Password updated"}


# ===================== API Keys =====================

@router.get("/admin/apikeys", response_model=List[ApiKeyOut], tags=["admin"])
async def list_api_keys(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return db.query(ApiKey).all()


@router.post("/admin/apikeys", response_model=ApiKeyCreated, status_code=201, tags=["admin"])
async def create_api_key(
    body: ApiKeyCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    raw = generate_api_key()
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    record = ApiKey(key_hash=key_hash, label=body.label, read_only=body.read_only)
    db.add(record)
    db.commit()
    db.refresh(record)
    return ApiKeyCreated(
        id=record.id,
        label=record.label,
        created_at=record.created_at,
        last_used_at=record.last_used_at,
        is_active=record.is_active,
        read_only=record.read_only,
        raw_key=raw,
    )


@router.delete("/admin/apikeys/{key_id}", status_code=204, tags=["admin"])
async def revoke_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    record = db.query(ApiKey).filter_by(id=key_id).first()
    if not record:
        raise HTTPException(status_code=404)
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
    body: ServiceSettingUpdate,
    _: User = Depends(require_admin),
):
    from database import set_service_setting
    if not body.value.strip():
        raise HTTPException(status_code=400, detail="API key cannot be empty")
    set_service_setting("anthropic_api_key", body.value.strip())
    return {"message": "Anthropic API key updated and encrypted in database."}


@router.delete("/admin/settings/anthropic-key", tags=["admin"])
async def delete_anthropic_key(_: User = Depends(require_admin)):
    from database import set_service_setting
    set_service_setting("anthropic_api_key", "")
    return {"message": "Anthropic API key removed."}


@router.put("/admin/settings/claude-model", tags=["admin"])
async def update_claude_model(
    body: ServiceSettingUpdate,
    _: User = Depends(require_admin),
):
    from database import set_service_setting
    set_service_setting("claude_model", body.value.strip())
    return {"message": f"Claude model updated to {body.value.strip()}"}
