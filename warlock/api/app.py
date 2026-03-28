"""Warlock GRC REST API -- Application factory.

All route handlers live in ``warlock.api.routers.*``.  This module
creates the FastAPI application, registers middleware, and mounts
the domain routers under ``/api/v1``.
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from starlette.responses import JSONResponse

from warlock.api.deps import get_db

from warlock import __version__ as _VERSION
from warlock.api.routers import (
    health,
    auth_routes,
    pipeline,
    compliance,
    governance,
    risk,
    admin,
    ai_routes,
    export,
    alerts,
    remediation,
    evidence,
    evidence_api,
    resources,
    trust_portal as trust_portal_router,
    webhooks,
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

            # Skip unauthenticated auth endpoints
            if path in (
                "/api/v1/auth/login",
                "/api/v1/auth/mfa",
                "/api/v1/auth/refresh",
            ):
                return await call_next(request)

            # Attach gate to request state for per-route use
            request.state.policy_gate = _policy_gate

            # Evaluate OPA policy if a user is present on the request
            user = getattr(request.state, "user", None)
            if user is not None:
                action = request.method.lower()
                allowed = await _policy_gate.evaluate(request, user, action)
                if not allowed:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Policy denied by OPA gate"},
                    )

            return await call_next(request)

    # ------------------------------------------------------------------
    # Prometheus /metrics endpoint (#7) — disabled in production
    # ------------------------------------------------------------------
    if not _is_production:
        try:
            from prometheus_client import make_asgi_app  # noqa: F401

            _metrics_app = make_asgi_app()
            application.mount("/metrics", _metrics_app)
            log.info("Prometheus /metrics endpoint mounted")
        except ImportError:
            pass  # prometheus_client not installed — /metrics endpoint unavailable
    else:
        log.info("Prometheus /metrics disabled in production (env=production)")

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
