# OpenAPI Schema Export

Warlock's FastAPI backend auto-generates an OpenAPI 3.1 specification. This document explains how to access and export it.

## Interactive Documentation

In non-production environments, two built-in UIs are available:

| Path | UI | Description |
|------|----|-------------|
| `/docs` | Swagger UI | Interactive "try it out" interface |
| `/redoc` | ReDoc | Read-only API reference with search |

Both require the API server to be running. Start it locally:

```bash
# From the project root
.venv/bin/python -m warlock.api.app
# or
uvicorn warlock.api.app:app --reload --port 8000
```

Then open `http://localhost:8000/docs` in your browser.

## Raw OpenAPI JSON

FastAPI exposes the machine-readable schema at `/openapi.json`. Export it with:

```bash
curl http://localhost:8000/openapi.json > openapi.json
```

The exported JSON includes every registered route, request/response models, query parameters, and error responses.

### Pipe to jq for inspection

```bash
# List all paths
curl -s http://localhost:8000/openapi.json | jq '.paths | keys'

# Count endpoints
curl -s http://localhost:8000/openapi.json | jq '.paths | keys | length'

# Extract a single endpoint's spec
curl -s http://localhost:8000/openapi.json | jq '.paths["/api/v1/auth/login"]'
```

## Production Behavior

When `WLK_ENV=production`, the `/docs`, `/redoc`, and `/openapi.json` endpoints are disabled. This is a security hardening measure -- the create_app() factory sets `docs_url=None` and `redoc_url=None` when the environment is production.

The raw `/openapi.json` endpoint is still served by FastAPI's default (it is not explicitly disabled), but the interactive UIs are not. If you need the schema in production for internal tooling, export it from a staging or development instance instead.

## Generating the Schema Without Running the Server

You can generate the OpenAPI JSON by importing the app object directly:

```python
#!/usr/bin/env python3
"""Export the Warlock OpenAPI schema to a JSON file."""

import json
import os

# Ensure we're not in production mode (which disables docs)
os.environ.setdefault("WLK_ENV", "development")

from warlock.api.app import create_app

app = create_app()
schema = app.openapi()

with open("openapi.json", "w") as f:
    json.dump(schema, f, indent=2)

print(f"Exported {len(schema.get('paths', {}))} paths to openapi.json")
```

Save this as `scripts/export_openapi.py` and run:

```bash
.venv/bin/python scripts/export_openapi.py
```

This approach does not start the HTTP server. It only builds the FastAPI app, extracts the schema in memory, and writes it to disk. A database connection is not required for schema generation.

## Using the Exported Schema

Common uses for the exported `openapi.json`:

- **Client generation** -- Feed it to [openapi-generator](https://openapi-generator.tech/) or [openapi-typescript](https://github.com/drwpow/openapi-typescript) to produce typed API clients.
- **API diffing** -- Compare schemas across versions to detect breaking changes. Tools like `oasdiff` automate this.
- **Documentation hosting** -- Import into Stoplight, Redocly, or any OpenAPI-compatible doc platform.
- **Postman / Insomnia** -- Import directly as a collection for manual testing.

## Schema Metadata

The generated schema includes:

| Field | Value |
|-------|-------|
| `title` | Warlock GRC API |
| `version` | Current package version from `warlock.__version__` |
| `description` | Compliance telemetry pipeline REST API |

Tags group endpoints by domain: health, auth, pipeline, compliance, governance, risk, admin, ai, export, alerts, remediation.
