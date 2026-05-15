"""
JWT-based authentication for the web UI + REST API.
API-key authentication for external Claude Project clients.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config import settings, PASSWORD_MIN_LENGTH
from database import ApiKey, User, get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

_MAX = 72  # bcrypt hard limit


def get_password_hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode()[:_MAX], _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode()[:_MAX], hashed.encode())
    except Exception:
        return False


def validate_password_strength(password: str) -> str | None:
    """Returns an error message if the password is too weak, else None."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if len(password) > _MAX:
        return f"Password must be {_MAX} characters or fewer."
    return None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


# ── Dependency helpers ────────────────────────────────────────────────────────

def _get_user_from_token(token: str, db: Session) -> Optional[User]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        token_version: int = payload.get("ver", 0)
        if not username:
            return None
    except JWTError:
        return None
    user = db.query(User).filter_by(username=username, is_active=True).first()
    if not user:
        return None
    # Token version mismatch means the token was invalidated (e.g. password changed)
    if getattr(user, "token_version", 0) != token_version:
        return None
    return user


def _get_user_from_api_key(raw_key: str, db: Session) -> Optional[User]:
    key_hash = _hash_api_key(raw_key)
    record = db.query(ApiKey).filter_by(key_hash=key_hash, is_active=True).first()
    if not record:
        return None
    record.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return User(username=f"apikey:{record.label}", is_active=True, is_admin=False)


async def get_current_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Security(bearer_scheme)],
    db: Session = Depends(get_db),
) -> User:
    raw = token or (credentials.credentials if credentials else None)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user = _get_user_from_token(raw, db) or _get_user_from_api_key(raw, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter_by(username=username, is_active=True).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
