"""Warlock GRC REST API -- Application factory.

All route handlers live in ``warlock.api.routers.*``.  This module
creates the FastAPI application, registers middleware, and mounts
the domain routers under ``/api/v1``.
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from starlette.responses import JSONResponse

from warlock import __version__ as _VERSION
from warlock.api.deps import get_db
from warlock.api.routers import (
    access_reviews,
    admin,
    ai_routes,
    alerts,
    analytics,
    auth_routes,
    bcp,
    calendar,
    changes,
    compliance,
    control_tests,
    evidence,
    evidence_api,
    exceptions,
    export,
    governance,
    health,
    incidents,
    pipeline,
    privacy,
    remediation,
    reports,
    resources,
    risk,
    search,
    training,
    webhooks,
)
from warlock.api.routers import (
    trust_portal as trust_portal_router,
)

log = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    from warlock.config import get_settings as _get_app_settings

    _app_settings = _get_app_settings()
    _is_production = _app_settings.env == "production"

    application = FastAPI(
        title="Warlock GRC API",
        version=_VERSION,
        description="Compliance telemetry pipeline REST API",
        docs_url=None if _is_production else "/docs",
        redoc_url=None if _is_production else "/redoc",
    )

    # ------------------------------------------------------------------
    # Structured logging
    # ------------------------------------------------------------------
    from warlock.logging_config import configure_logging

    configure_logging()

    # ------------------------------------------------------------------
    # Production config validation (GAP-077 SSO, secrets, CORS)
    # ------------------------------------------------------------------
    # Note: _get_app_settings() is already loaded above.
    if _app_settings.env == "production":
        from warlock.config import validate_production_config

        validate_production_config(_app_settings)

    # ------------------------------------------------------------------
    # CORS — configured via WLK_CORS_ORIGINS
    # ------------------------------------------------------------------
    from warlock.config import get_settings as _get_cors_settings

    _cors_settings = _get_cors_settings()
    if _cors_settings.cors_origins:
        # S-10: Reject wildcard origin when credentials are enabled
        if "*" in _cors_settings.cors_origins:
            raise RuntimeError(
                "CORS misconfiguration: allow_origins contains '*' with allow_credentials=True. "
                "This is insecure and forbidden by the CORS specification. "
                "Set WLK_CORS_ORIGINS to specific origins, not '*'."
            )
        from fastapi.middleware.cors import CORSMiddleware

        application.add_middleware(
            CORSMiddleware,
            allow_origins=_cors_settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
            allow_headers=["Authorization", "X-Api-Key", "Content-Type"],
        )

    # ------------------------------------------------------------------
    # Security middleware (rate limiting, security headers, audit logging)
    # ------------------------------------------------------------------
    from warlock.api.middleware import register_middleware

    register_middleware(application)

    # ------------------------------------------------------------------
    # S-18: Request size limit — reject requests larger than 10MB
    # ------------------------------------------------------------------
    _MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

    @application.middleware("http")
    async def request_size_limit_middleware(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > _MAX_CONTENT_LENGTH:
            from starlette.responses import Response

            return Response(
                content='{"detail":"Request body too large (max 10MB)"}',
                status_code=413,
                media_type="application/json",
            )
        return await call_next(request)

    # ------------------------------------------------------------------
    # Trust portal (public, no auth)
    # ------------------------------------------------------------------
    from warlock.api.trust_portal import router as trust_router

    application.include_router(trust_router)

    # ------------------------------------------------------------------
    # OPA policy gate (optional)
    # ------------------------------------------------------------------
    from warlock.api.policy_gate import get_policy_gate

    _policy_gate = get_policy_gate()

    if _policy_gate.enabled:

        @application.middleware("http")
        async def opa_policy_middleware(request: Request, call_next):
            # Skip trust portal (public) and health endpoints
            path = request.url.path
            if (
                path.startswith("/trust")
                or path in ("/health", "/healthz", "/readyz")
                or path.endswith("/health")
            ):
                return await call_next(request)

            # F23: Genuinely-public path allowlist — these routes either
            # have their own authentication (signed webhooks, OAuth code
            # exchange, SSO callback) or serve the public trust portal /
            # documentation. Everything ELSE goes through OPA, even when
            # there is no authenticated user, so unauthenticated routes
            # cannot silently bypass policy.
            _PUBLIC_OPA_BYPASS = (
                "/api/v1/auth/login",
                "/api/v1/auth/mfa",
                "/api/v1/auth/refresh",
                "/api/v1/auth/register",
                "/api/v1/auth/password-reset",
                "/api/v1/auth/sso/login",
                "/api/v1/auth/sso/callback",
            )
            _PUBLIC_OPA_BYPASS_PREFIXES = (
                "/api/v1/trust/",  # public trust portal
                "/static/",  # SPA assets
                "/docs",  # FastAPI auto docs (only when not in prod)
                "/redoc",
                "/openapi.json",
            )
            if path in _PUBLIC_OPA_BYPASS or any(
                path.startswith(p) for p in _PUBLIC_OPA_BYPASS_PREFIXES
            ):
                return await call_next(request)

            # Attach gate to request state for per-route use
            request.state.policy_gate = _policy_gate

            # F23: evaluate OPA for ALL non-public requests (not just those
            # with an authenticated user). PolicyGate.evaluate handles
            # user=None by sending email/role="anonymous" to OPA so policy
            # authors can write rules for unauthenticated paths.
            user = getattr(request.state, "user", None)
            action = request.method.lower()
            allowed = await _policy_gate.evaluate(request, user, action)
            if not allowed:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Policy denied by OPA gate"},
                )

            return await call_next(request)

    # ------------------------------------------------------------------
    # N1 fix: Auth resolver — registered AFTER opa_policy_middleware so
    # Starlette's LIFO middleware order has it run BEFORE OPA on the inbound
    # path. Populates `request.state.user` so the OPA gate sees the actual
    # role instead of always "anonymous". Non-enforcing — invalid credentials
    # do NOT raise here; the per-route `Depends(require_permission(...))`
    # still does the rejection. Cost is one DB lookup per authenticated
    # request; this gets de-duplicated by the Depends machinery downstream.
    # ------------------------------------------------------------------
    @application.middleware("http")
    async def auth_resolver_middleware(request: Request, call_next):
        try:
            from warlock.api.auth import authenticate_api_key, decode_access_token
            from warlock.db.engine import get_session
        except Exception:
            return await call_next(request)

        api_key = request.headers.get("x-api-key")
        authz = request.headers.get("authorization", "")

        if api_key:
            try:
                with get_session() as session:
                    user, _ = authenticate_api_key(session, api_key)
                    if user is not None:
                        request.state.user = user
            except Exception:
                pass  # never block the request from middleware
        elif authz.lower().startswith("bearer "):
            try:
                payload = decode_access_token(authz[7:].strip())
                sub = payload.get("sub")
                if sub:
                    from warlock.db.models import User

                    with get_session() as session:
                        user = session.query(User).filter(User.email == sub).first()
                        if user is not None and user.is_active:
                            request.state.user = user
            except Exception:
                pass  # invalid token — let per-route auth surface raise the 401

        return await call_next(request)

    # ------------------------------------------------------------------
    # Prometheus /metrics endpoint (#7) — disabled in production
    # ------------------------------------------------------------------
    if not _is_production:
        try:
            from prometheus_client import make_asgi_app

            _metrics_app = make_asgi_app()
            application.mount("/metrics", _metrics_app)
            log.info("Prometheus /metrics endpoint mounted")
        except ImportError:
            pass  # prometheus_client not installed — /metrics endpoint unavailable
    else:
        log.info("Prometheus /metrics disabled in production (env=production)")

    # ------------------------------------------------------------------
    # API versioning — deprecation headers and v2 redirect stub (Item 113)
    # ------------------------------------------------------------------
    @application.middleware("http")
    async def api_versioning_middleware(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/api/v1"):
            response.headers["Deprecation"] = "false"
            response.headers["Sunset"] = ""
            response.headers["X-API-Version"] = "v1"
        elif path.startswith("/api/v2"):
            # v2 stub — redirect to v1 for now
            from starlette.responses import Response

            return Response(
                content='{"detail":"API v2 not yet available. Use /api/v1."}',
                status_code=501,
                media_type="application/json",
                headers={"X-API-Version": "v2"},
            )
        return response

    # ------------------------------------------------------------------
    # Mount domain routers
    # ------------------------------------------------------------------
    prefix = "/api/v1"

    application.include_router(health.router, prefix=prefix, tags=["health"])
    application.include_router(auth_routes.router, prefix=prefix, tags=["auth"])
    application.include_router(pipeline.router, prefix=prefix, tags=["pipeline"])
    application.include_router(compliance.router, prefix=prefix, tags=["compliance"])
    application.include_router(governance.router, prefix=prefix, tags=["governance"])
    application.include_router(risk.router, prefix=prefix, tags=["risk"])
    application.include_router(admin.router, prefix=prefix, tags=["admin"])
    application.include_router(ai_routes.router, prefix=prefix, tags=["ai"])
    application.include_router(export.router, prefix=prefix, tags=["export"])
    application.include_router(alerts.router, prefix=prefix, tags=["alerts"])
    application.include_router(remediation.router, prefix=prefix, tags=["remediation"])
    application.include_router(evidence.router, prefix=prefix, tags=["evidence"])
    application.include_router(evidence_api.router, prefix=prefix, tags=["evidence-portal"])
    application.include_router(resources.router, prefix=prefix, tags=["resources"])
    application.include_router(webhooks.router, prefix=prefix, tags=["webhooks"])
    application.include_router(trust_portal_router.router, prefix=prefix, tags=["trust-portal"])
    application.include_router(analytics.router, prefix=prefix, tags=["analytics"])
    application.include_router(search.router, prefix=prefix, tags=["search"])
    application.include_router(reports.router, prefix=prefix, tags=["reports"])
    application.include_router(incidents.router, prefix=prefix, tags=["incidents"])
    application.include_router(changes.router, prefix=prefix, tags=["changes"])
    application.include_router(calendar.router, prefix=prefix, tags=["calendar"])
    application.include_router(exceptions.router, prefix=prefix, tags=["exceptions"])
    application.include_router(privacy.router, prefix=prefix, tags=["privacy"])
    application.include_router(access_reviews.router, prefix=prefix, tags=["access-reviews"])
    application.include_router(training.router, prefix=prefix, tags=["training"])
    application.include_router(bcp.router, prefix=prefix, tags=["bcp"])
    application.include_router(control_tests.router, prefix=prefix, tags=["control-tests"])

    # Real-time webhook ingestion (Item 60)
    from warlock.pipeline.webhook_receiver import router as ingest_router

    application.include_router(ingest_router, prefix=prefix, tags=["ingest"])

    # WebSocket endpoint for real-time events
    from warlock.api.websocket import router as ws_router

    application.include_router(ws_router, prefix=prefix, tags=["websocket"])

    # SSE endpoint for real-time compliance events (Item 114)
    from warlock.api.sse import router as sse_router

    application.include_router(sse_router, prefix=prefix, tags=["events"])

    # Mobile-compact endpoints (Item 131)
    from warlock.api.mobile import router as mobile_router

    application.include_router(mobile_router, prefix=prefix, tags=["mobile"])

    # ------------------------------------------------------------------
    # Root-level health endpoints for k8s probes, load balancers, Docker
    # ------------------------------------------------------------------
    application.include_router(health.router, tags=["health"])

    @application.get("/healthz", tags=["health"])
    def healthz():
        """Alias for /health — standard k8s liveness probe path."""
        return health.health()

    @application.get("/readyz", tags=["health"])
    def readyz(db=Depends(get_db)):
        """Alias for /health/ready — standard k8s readiness probe path."""
        return health.health_ready(db)

    # ------------------------------------------------------------------
    # ARCH-020: Mount frontend SPA static files (if built)
    # ------------------------------------------------------------------
    from pathlib import Path

    _static_dir = Path(__file__).resolve().parent.parent.parent / "static"
    if _static_dir.is_dir() and (_static_dir / "index.html").exists():
        from starlette.staticfiles import StaticFiles

        application.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="frontend")
        log.info("Frontend SPA mounted from %s", _static_dir)

    return application


# Module-level app instance (used by uvicorn and console entry point)
app = create_app()


# =========================================================================
# Server entry point
# =========================================================================


def run_server():
    """Entry point for `warlock-api` console script."""
    import uvicorn

    from warlock.config import get_settings

    settings = get_settings()

    uvicorn.run(
        "warlock.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )
