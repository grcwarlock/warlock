# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Stage 1: Builder — install Python dependencies with full build toolchain
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libffi-dev \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency manifest first (layer caching — changes less often than source)
COPY pyproject.toml ./

# Install warlock with all production extras
# Uses cache mount to speed up rebuilds
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-compile --prefix=/install \
        ".[aws,azure,gcp,ai,monitoring,lake,pdf,graphql]" \
        gunicorn uvicorn[standard]

# -----------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only what is needed to run
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Runtime system dependencies (libpq for psycopg2, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system warlock && \
    useradd --system --gid warlock --create-home warlock

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
WORKDIR /app
COPY --chown=warlock:warlock warlock/ ./warlock/
COPY --chown=warlock:warlock alembic.ini ./alembic.ini
COPY --chown=warlock:warlock pyproject.toml ./pyproject.toml
COPY --chown=warlock:warlock policies/ ./policies/
COPY --chown=warlock:warlock frameworks-oscal/ ./frameworks-oscal/

# Copy and set entrypoint
COPY --chown=warlock:warlock terraform/modules/deploy/container-image/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Install the package itself (editable so warlock CLI entry point works)
RUN pip install --no-deps -e .

# Switch to non-root user
USER warlock

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "warlock.api.app:app", \
     "-w", "4", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "-b", "0.0.0.0:8000", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
