# ---------- builder ----------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .

# ---------- runtime ----------
FROM python:3.12-slim

WORKDIR /app

# Runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r warlock && useradd -r -g warlock -d /app -s /sbin/nologin warlock

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY warlock/ ./warlock/
COPY scripts/ ./scripts/

RUN chown -R warlock:warlock /app

USER warlock

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "warlock.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]
