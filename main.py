"""
Syslog Retention & SIEM Service — entry point.
"""
import asyncio
import logging
import os
import stat
import sys
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from time import time
from typing import Callable

if sys.version_info < (3, 10):
    print(
        f"ERROR: Python 3.10+ required (found {sys.version_info.major}.{sys.version_info.minor}). Exiting.",
        file=sys.stderr,
    )
    sys.exit(1)

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from database import init_db, SessionLocal, purge_old_entries, _resolved_db_path
from syslog_listener import start_udp_listener, start_tcp_listener
from netflow_listener import start_netflow_listener
from api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("main")

_udp_transport = None
_tcp_server = None
_netflow_transport = None
_background_tasks: list[asyncio.Task] = []

# ── Login rate limiter ────────────────────────────────────────────────────────
# Maps IP → list of attempt timestamps within the window
_login_attempts: dict[str, list[float]] = defaultdict(list)
_login_lock = asyncio.Lock()


async def record_login_attempt(ip: str) -> bool:
    """Returns True if the attempt is allowed, False if the IP is locked out."""
    from database import get_service_setting
    async with _login_lock:
        now = time()
        window = int(get_service_setting("login_lockout_seconds") or settings.login_lockout_seconds)
        max_attempts = int(get_service_setting("login_max_attempts") or settings.login_max_attempts)
        attempts = [t for t in _login_attempts[ip] if now - t < window]
        _login_attempts[ip] = attempts
        if len(attempts) >= max_attempts:
            return False
        _login_attempts[ip].append(now)
        return True


def clear_login_attempts(ip: str) -> None:
    _login_attempts.pop(ip, None)


# ── Startup / shutdown ────────────────────────────────────────────────────────

def _do_purge() -> int:
    db = SessionLocal()
    try:
        return purge_old_entries(db)
    finally:
        db.close()


async def _scheduled_purge():
    while True:
        await asyncio.sleep(86400)
        try:
            deleted = await asyncio.to_thread(_do_purge)
            if deleted:
                logger.info("Scheduled purge: removed %d entries", deleted)
        except Exception as exc:
            logger.error("Scheduled purge failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _udp_transport, _tcp_server, _netflow_transport

    try:
        init_db()
    except Exception as exc:
        logger.critical("DATABASE INIT FAILED — service cannot start: %s", exc, exc_info=True)
        logger.critical("Check that DB_PATH directory exists and is writable by the service user.")
        logger.critical("DB_PATH = %s", settings.db_path)
        raise  # re-raise so uvicorn exits; error is now in the log file

    logger.info("Database initialised at %s", _resolved_db_path)

    # Lock down DB file permissions — use the resolved path (may differ from
    # settings.db_path when the M.2 drive is unavailable and we fell back to
    # local storage). Guard with try/except so an I/O error on a failing drive
    # does not abort startup.
    try:
        db_path = Path(_resolved_db_path)
        if db_path.exists():
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        logger.warning("Could not set DB file permissions: %s", exc)

    try:
        _udp_transport = await start_udp_listener(settings.syslog_udp_host, settings.syslog_udp_port)
    except OSError as exc:
        logger.warning("UDP listener failed (port %d): %s", settings.syslog_udp_port, exc)

    try:
        _tcp_server = await start_tcp_listener(settings.syslog_tcp_host, settings.syslog_tcp_port)
    except OSError as exc:
        logger.warning("TCP listener failed (port %d): %s", settings.syslog_tcp_port, exc)

    from database import get_service_setting
    _nf_enabled_raw = get_service_setting("netflow_enabled")
    _nf_enabled = settings.netflow_enabled if _nf_enabled_raw is None else (_nf_enabled_raw.lower() == "true")
    _nf_port = int(get_service_setting("netflow_port") or settings.netflow_port)
    if _nf_enabled:
        try:
            _netflow_transport = await start_netflow_listener(settings.netflow_host, _nf_port)
        except OSError as exc:
            logger.warning("NetFlow listener failed (port %d): %s", _nf_port, exc)

    from alert_engine import run_alert_engine
    _background_tasks.append(asyncio.create_task(_scheduled_purge(), name="purge"))
    _background_tasks.append(asyncio.create_task(run_alert_engine(), name="alert_engine"))
    logger.info(
        "Web console: http://%s:%d",
        "localhost" if settings.api_host == "0.0.0.0" else settings.api_host,
        settings.api_port,
    )

    yield

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    logger.info("Shutting down background tasks...")
    for task in _background_tasks:
        task.cancel()
    # Cancel any in-flight AI analysis jobs
    from api.routes import _analysis_jobs
    for job in _analysis_jobs.values():
        t = job.get("_task")
        if t and not t.done():
            t.cancel()
    # Wait up to 5 s for tasks to acknowledge cancellation
    if _background_tasks:
        await asyncio.wait(_background_tasks, timeout=5)
    _background_tasks.clear()

    if _udp_transport:
        _udp_transport.close()
    if _netflow_transport:
        _netflow_transport.close()
    if _tcp_server:
        _tcp_server.close()
        try:
            await asyncio.wait_for(_tcp_server.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            logger.warning("TCP server did not close cleanly within 5s")
    logger.info("Shutdown complete.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.service_display_name,
    description="Syslog ingestion, retention, and AI-powered security analysis.",
    version="1.0.0",
    lifespan=lifespan,
    # Disable auto-generated docs — they expose the full API surface unauthenticated
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Rate-limit middleware (applied to login endpoint only) ────────────────────

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Callable) -> Response:
    if request.url.path == "/api/auth/token" and request.method == "POST":
        ip = request.client.host if request.client else "unknown"
        if not await record_login_attempt(ip):
            logger.warning("Login rate limit exceeded for %s", ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many login attempts. Try again in 5 minutes."},
            )
    return await call_next(request)


# ── Routes ────────────────────────────────────────────────────────────────────

app.include_router(router, prefix="/api")

_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/health", include_in_schema=False)
async def health():
    """Liveness probe — returns 200 if the service and DB are reachable."""
    try:
        from database import SessionLocal, SyslogEntry
        db = SessionLocal()
        db.query(SyslogEntry).limit(1).all()
        db.close()
        return {"status": "ok"}
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        return JSONResponse(status_code=503, content={"status": "unhealthy"})


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(str(_static_dir / "index.html"))


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        reload=False,
    )
