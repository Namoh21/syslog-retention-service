"""
Syslog Retention & SIEM Service
Entry point — starts FastAPI + syslog listeners.
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from database import init_db, SessionLocal, purge_old_entries
from syslog_listener import start_udp_listener, start_tcp_listener
from api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("main")

_udp_transport = None
_tcp_server = None


async def _scheduled_purge():
    """Run retention purge daily."""
    while True:
        await asyncio.sleep(86400)  # 24 hours
        try:
            db = SessionLocal()
            deleted = purge_old_entries(db)
            db.close()
            if deleted:
                logger.info("Scheduled purge: removed %d entries", deleted)
        except Exception as exc:
            logger.error("Scheduled purge failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _udp_transport, _tcp_server

    # Initialise DB + seed admin account
    init_db()
    logger.info("Database initialised at %s", settings.db_path)

    # Start syslog listeners
    try:
        _udp_transport = await start_udp_listener(settings.syslog_udp_host, settings.syslog_udp_port)
    except OSError as exc:
        logger.warning("UDP listener failed (port %d): %s — try running as Administrator or change SYSLOG_UDP_PORT", settings.syslog_udp_port, exc)

    try:
        _tcp_server = await start_tcp_listener(settings.syslog_tcp_host, settings.syslog_tcp_port)
    except OSError as exc:
        logger.warning("TCP listener failed (port %d): %s", settings.syslog_tcp_port, exc)

    asyncio.create_task(_scheduled_purge())

    logger.info("Web console available at http://%s:%d", settings.api_host if settings.api_host != '0.0.0.0' else 'localhost', settings.api_port)

    yield

    # Shutdown
    if _udp_transport:
        _udp_transport.close()
    if _tcp_server:
        _tcp_server.close()
        await _tcp_server.wait_closed()


app = FastAPI(
    title=settings.service_display_name,
    description="Syslog ingestion, retention, and AI-powered security analysis.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST API
app.include_router(router, prefix="/api")

# Serve web GUI
_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


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
