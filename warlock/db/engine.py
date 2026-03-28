"""Database engine and session management.

Multi-tenancy
-------------
When ``WLK_MULTI_TENANCY_ENABLED=true``, every ORM SELECT issued through
:func:`get_session` or :func:`get_read_session` is automatically filtered
by the *current tenant*.  The tenant is determined by the :data:`current_tenant_id`
ContextVar which API middleware sets per-request.

CLI commands and the demo seed run outside the request cycle and therefore
always use the default tenant (``DEFAULT_TENANT_ID``).
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from warlock.config import get_settings

# Tenant context — set per-request by API middleware, defaults to system tenant.
current_tenant_id: ContextVar[str | None] = ContextVar("current_tenant_id", default=None)

_engine = None
_session_factory = None
_read_engine = None
_read_session_factory = None


def _is_pgbouncer_mode(settings) -> bool:
    """Return True when WLK_PGBOUNCER_MODE=true."""
    return str(getattr(settings, "pgbouncer_mode", "false")).lower() == "true"


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {}
        if settings.database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        pool_kwargs = {}
        if not settings.database_url.startswith("sqlite"):
            if _is_pgbouncer_mode(settings):
                # PgBouncer transaction-mode: single connection per checkout,
                # no prepared statements (server-side cursors are disallowed).
                # NOTE: pool_size=1 + max_overflow=0 means this worker holds
                # exactly one DB connection at a time.  All requests within a
                # single uvicorn worker are serialized behind that connection.
                # To achieve concurrency, run multiple uvicorn workers
                # (e.g. ``uvicorn --workers 4``).  Each worker gets its own
                # pool_size=1 connection, and PgBouncer multiplexes them.
                pool_kwargs = {
                    "pool_size": 1,
                    "max_overflow": 0,
                    "pool_recycle": 3600,
                    "pool_timeout": 30,
                }
                connect_args["prepared_statement_cache_size"] = 0
            else:
                pool_kwargs = {
                    "pool_size": 10,
                    "max_overflow": 20,
                    "pool_recycle": 3600,
                    "pool_timeout": 30,
                }
        _engine = create_engine(
            settings.database_url,
            connect_args=connect_args,
            pool_pre_ping=True,
            **pool_kwargs,
        )
        # Enable FK enforcement on SQLite (it's off by default)
        if settings.database_url.startswith("sqlite"):

            @event.listens_for(_engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.close()

        else:
            # ARCH-009: Set statement timeout for PostgreSQL connections.
            timeout_ms = getattr(settings, "query_timeout_ms", 30000)

            @event.listens_for(_engine, "connect")
            def _set_pg_statement_timeout(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute(f"SET statement_timeout = '{timeout_ms}'")
                cursor.close()

    return _engine


def get_read_engine():
    """Return a SQLAlchemy engine pointed at the read replica.

    Falls back to the primary engine when WLK_DATABASE_READ_URL is not set.
    Applies PgBouncer pool settings when WLK_PGBOUNCER_MODE=true.
    """
    global _read_engine
    if _read_engine is None:
        settings = get_settings()
        read_url = getattr(settings, "database_read_url", "") or ""
        if not read_url:
            # No dedicated replica — reuse primary engine.
            _read_engine = get_engine()
        else:
            connect_args = {}
            pool_kwargs = {}
            if not read_url.startswith("sqlite"):
                if _is_pgbouncer_mode(settings):
                    pool_kwargs = {
                        "pool_size": 1,
                        "max_overflow": 0,
                        "pool_recycle": 3600,
                        "pool_timeout": 30,
                    }
                    connect_args["prepared_statement_cache_size"] = 0
                else:
                    pool_kwargs = {
                        "pool_size": 10,
                        "max_overflow": 20,
                        "pool_recycle": 3600,
                        "pool_timeout": 30,
                    }
            _read_engine = create_engine(
                read_url,
                connect_args=connect_args,
                pool_pre_ping=True,
                **pool_kwargs,
            )
    return _read_engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _session_factory


def get_read_session_factory():
    """Return a session factory bound to the read replica engine."""
    global _read_session_factory
    if _read_session_factory is None:
        _read_session_factory = sessionmaker(
            bind=get_read_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _read_session_factory


@contextmanager
def get_session() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def get_read_session() -> Generator[Session, None, None]:
    """Context manager for a read-only session against the replica.

    Does not commit — callers must not mutate state through this session.
    Falls back transparently to the primary when no read URL is configured.
    """
    session = get_read_session_factory()()
    try:
        # Enforce read-only at the database level for PostgreSQL connections.
        # SQLite does not support SET TRANSACTION READ ONLY, so skip it.
        bind_url = str(session.get_bind().url)
        if bind_url.startswith("postgresql"):
            session.execute(text("SET TRANSACTION READ ONLY"))
        yield session
    finally:
        session.close()


def init_db():
    """Create all tables. For development — use Alembic in production.

    Also ensures the default system tenant exists so that FK constraints
    on ``tenant_id`` columns are satisfied for all subsequent inserts.
    """
    from warlock.db.models import Base, DEFAULT_TENANT_ID, Tenant  # noqa: F811

    Base.metadata.create_all(get_engine())
    _ensure_default_tenant(Tenant, DEFAULT_TENANT_ID)
    _install_tenant_filter()


def _ensure_default_tenant(tenant_cls, default_id: str) -> None:
    """Insert the default system tenant if it doesn't exist."""
    session = get_session_factory()()
    try:
        existing = session.query(tenant_cls).filter(tenant_cls.id == default_id).first()
        if not existing:
            session.add(tenant_cls(id=default_id, name="System", slug="system", is_active=True))
            session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


_tenant_filter_installed = False


def _install_tenant_filter() -> None:
    """Install a session-level ORM event that auto-applies tenant_id filters.

    Only active when ``WLK_MULTI_TENANCY_ENABLED=true``.  The filter is a
    ``do_orm_execute`` event that appends ``WHERE tenant_id = :tid`` to every
    SELECT whose primary entity has a ``tenant_id`` column.
    """
    global _tenant_filter_installed  # noqa: PLW0603
    if _tenant_filter_installed:
        return
    _tenant_filter_installed = True

    settings = get_settings()
    if not settings.multi_tenancy_enabled:
        return

    from warlock.db.models import Tenant, TenantMixin  # noqa: F811

    @event.listens_for(Session, "do_orm_execute")
    def _apply_tenant_filter(orm_execute_state):
        """Auto-apply ``WHERE tenant_id = ?`` to every tenant-scoped SELECT."""
        if not orm_execute_state.is_select:
            return
        if orm_execute_state.execution_options.get("skip_tenant_filter", False):
            return
        tid = current_tenant_id.get()
        if tid is None:
            tid = settings.default_tenant_id

        mapper = orm_execute_state.bind_mapper
        if mapper is None:
            return
        entity = mapper.class_
        if entity is Tenant:
            return
        if not isinstance(entity, type) or not issubclass(entity, TenantMixin):
            return
        # Use filter_criteria to add the tenant condition
        orm_execute_state.statement = orm_execute_state.statement.where(entity.tenant_id == tid)
