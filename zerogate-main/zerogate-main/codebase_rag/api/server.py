"""ZeroGate FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from loguru import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler — startup and shutdown."""
    logger.info("ZeroGate API server starting...")

    # Create upload directory
    upload_dir = Path("/tmp/zerogate/projects")
    upload_dir.mkdir(parents=True, exist_ok=True)

    yield

    logger.info("ZeroGate API server shutting down...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="ZeroGate — The Autonomous Security Graph",
        description=(
            "ZeroGate is an autonomous, local-first security graph engine "
            "that constructs a dynamic graph of a target codebase and "
            "intelligently maps logical paths to potential vulnerabilities."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routes ────────────────────────────────────────────────────────
    from codebase_rag.api.routes.findings import router as findings_router
    from codebase_rag.api.routes.projects import router as projects_router
    from codebase_rag.api.routes.websocket import router as ws_router
    from codebase_rag.api.routes.github import router as github_router
    from codebase_rag.api.routes.settings import router as settings_router

    app.include_router(projects_router, prefix="/api")
    app.include_router(findings_router, prefix="/api")
    app.include_router(github_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(ws_router)

    # ── Health check ──────────────────────────────────────────────────
    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "zerogate"}

    # ── Serve frontend static files (if built) ────────────────────────
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if frontend_dist.exists():
        app.mount(
            "/",
            StaticFiles(directory=str(frontend_dist), html=True),
            name="frontend",
        )

    return app


# For `uvicorn codebase_rag.api.server:app`
app = create_app()
