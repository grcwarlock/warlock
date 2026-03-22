#!/bin/bash
# Docker demo entrypoint — migrate, seed, serve.
# Usage: called as ENTRYPOINT in docker-compose demo service
set -e

echo "============================================================"
echo "  Warlock Demo — Docker"
echo "============================================================"
echo ""

# 1. Wait for Postgres (belt-and-suspenders beyond depends_on)
echo "[1/4] Waiting for database..."
for i in $(seq 1 30); do
    if python -c "
from sqlalchemy import create_engine, text
e = create_engine('$WLK_DATABASE_URL')
with e.connect() as c: c.execute(text('SELECT 1'))
" 2>/dev/null; then
        echo "       Database ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Database not available after 30s"
        exit 1
    fi
    sleep 1
done

# 2. Create schema
echo "[2/4] Creating database schema..."
# Use create_all for fresh Postgres — Alembic batch mode has SQLite-specific
# constraint naming that breaks on Postgres. For the demo, we always start fresh.
python -c "
from warlock.db.models import Base
from sqlalchemy import create_engine
import os
engine = create_engine(os.environ['WLK_DATABASE_URL'])
Base.metadata.create_all(engine)
engine.dispose()
print('       Schema created.')
"

# 3. Seed demo data
echo "[3/4] Seeding demo environment..."
SEED_OUTPUT=$(python scripts/demo_seed.py 2>&1)
echo "$SEED_OUTPUT" | grep -E "^\[|Connectors succeeded|Connectors failed|Raw events|Findings normalized|Controls mapped|Seed complete|Lake writer" || true
echo ""

# Validate seed output
SUCCEEDED=$(echo "$SEED_OUTPUT" | grep "Connectors succeeded" | grep -oE '[0-9]+' | tail -1)
FAILED=$(echo "$SEED_OUTPUT" | grep "Connectors failed" | grep -oE '[0-9]+' | tail -1)

if [ "${FAILED:-1}" != "0" ]; then
    echo "WARNING: ${FAILED} connectors failed (expected 0)"
fi
if [ "${SUCCEEDED:-0}" -lt 81 ]; then
    echo "WARNING: Only ${SUCCEEDED} connectors succeeded (expected 81)"
fi

echo "       Seed complete: ${SUCCEEDED:-?} connectors, ${FAILED:-?} failures"
echo ""

# 4. Start API server
echo "[4/4] Starting API server on port 8000..."
echo ""
echo "============================================================"
echo "  Demo is live!"
echo "============================================================"
echo ""
echo "  API:    http://localhost:8000/api/v1/health"
echo "  Docs:   http://localhost:8000/docs"
echo ""
echo "  Sample queries:"
echo "    curl http://localhost:8000/api/v1/coverage"
echo "    curl http://localhost:8000/api/v1/findings?limit=5"
echo "    curl http://localhost:8000/api/v1/frameworks"
echo ""
echo "  Login:  admin@acme.com / WarlockAdmin2026!"
echo ""
echo "  Stop:   docker compose down"
echo "  Reset:  docker compose down -v && docker compose up demo"
echo "============================================================"
echo ""

# exec into the API server so signals propagate correctly
exec warlock-api
