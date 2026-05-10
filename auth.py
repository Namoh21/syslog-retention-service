"""
JWT-based authentication for the web UI + REST API.
API-key authentication for external Claude Project clients.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from config import settings
from database import ApiKey, User, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload["exp"] = expire
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


# ---- dependency helpers ----

def _get_user_from_token(token: str, db: Session) -> Optional[User]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if not username:
            return None
    except JWTError:
        return None
    return db.query(User).filter_by(username=username, is_active=True).first()


def _get_user_from_api_key(raw_key: str, db: Session) -> Optional[User]:
    # Check env-configured static keys first (for Claude Projects)
    if raw_key in settings.get_external_api_keys():
        return User(username="claude_project", is_active=True, is_admin=False)

    # Check DB-stored keys
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

    # Try JWT first, then API key
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
