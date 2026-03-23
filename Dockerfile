# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.12

# --- Builder: install dependencies only ---
FROM python:${PYTHON_VERSION}-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml .
COPY warlock/__init__.py warlock/__init__.py
ARG EXTRAS=""
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ -n "$EXTRAS" ]; then pip install --prefix=/install ".[$EXTRAS]"; \
    else pip install --prefix=/install .; fi

# --- Runtime ---
FROM python:${PYTHON_VERSION}-slim AS runtime
RUN groupadd --gid 1001 warlock && useradd --uid 1001 --gid warlock --no-create-home warlock
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /install /usr/local
COPY warlock/ warlock/
COPY alembic.ini .
COPY pyproject.toml .
COPY scripts/demo_seed.py scripts/demo_seed.py
COPY scripts/demo_data.py scripts/demo_data.py
COPY scripts/demo_connectors_new.py scripts/demo_connectors_new.py
COPY scripts/docker-demo.sh scripts/docker-demo.sh
RUN chmod +x scripts/docker-demo.sh
# Reinstall warlock itself (not deps) so entry points resolve against full source
RUN pip install --no-deps -e . 2>/dev/null || pip install --no-deps .
RUN mkdir -p /data /app/lake && chown -R warlock:warlock /data /app/lake
USER warlock:warlock
ENV WLK_DATABASE_URL=sqlite:////data/warlock.db \
    WLK_API_HOST=0.0.0.0 \
    WLK_API_PORT=8000 \
    WLK_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
ENTRYPOINT ["warlock-api"]
