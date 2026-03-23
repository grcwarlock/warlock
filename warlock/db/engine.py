"""Database engine and session management."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from warlock.config import get_settings

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
            from sqlalchemy import event

            @event.listens_for(_engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
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
    """Create all tables. For development — use Alembic in production."""
    from warlock.db.models import Base  # noqa: F811

    Base.metadata.create_all(get_engine())
