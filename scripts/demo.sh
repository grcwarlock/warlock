#!/bin/bash
# Spin up a fully operational Warlock demo in one command.
# Usage: ./scripts/demo.sh
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

echo "============================================================"
echo "  Warlock Demo — Full Stack"
echo "============================================================"
echo ""

# 1. Activate venv
if [ ! -d ".venv" ]; then
    echo "[1/6] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/6] Virtual environment exists."
fi
source .venv/bin/activate

# 2. Install
echo "[2/6] Installing dependencies..."
pip install -e ".[dev,ai]" --quiet 2>/dev/null

# 3. Kill anything on our ports
echo "[3/6] Clearing ports..."
lsof -ti:8000 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti:8181 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# 4. Start OPA server with policy bundle
if command -v opa &>/dev/null; then
    echo "[4/6] Starting OPA server (port 8181)..."
    opa run --server --addr :8181 --bundle policies/ &>/dev/null &
    OPA_PID=$!
    sleep 2
    if kill -0 $OPA_PID 2>/dev/null; then
        export WLK_OPA_COMPLIANCE_ENABLED=true
        export WLK_OPA_COMPLIANCE_URL=http://localhost:8181/v1/data
        echo "       OPA running (PID $OPA_PID) — compliance policies active"
    else
        echo "       OPA failed to start — running without policy evaluation"
    fi
else
    echo "[4/6] OPA not installed — skipping policy evaluation"
    echo "       Install with: brew install opa"
fi

# 5. Fresh database + seed
echo "[5/6] Seeding demo environment..."
rm -f warlock.db
alembic upgrade head 2>&1 | tail -1
python scripts/demo_seed.py 2>&1 | grep -E "^\[|^  Raw|^  Find|^  Cont|^  Conn|^  Dur|Seed complete"
echo ""

# 6. Start API server
echo "[6/6] Starting API server (port 8000)..."
warlock-api &>/dev/null &
API_PID=$!
sleep 2

if kill -0 $API_PID 2>/dev/null; then
    echo ""
    echo "============================================================"
    echo "  Demo is live!"
    echo "============================================================"
    echo ""
    echo "  CLI:  warlock coverage"
    echo "        warlock findings"
    echo "        warlock results --status non_compliant"
    echo "        warlock poams"
    echo "        warlock drift"
    echo "        warlock systems"
    echo "        warlock vendors"
    echo "        warlock retention report"
    echo ""
    echo "  API:  ./scripts/demo_api.sh"
    echo "        ./scripts/demo_api.sh /api/v1/findings?limit=5"
    echo "        ./scripts/demo_api.sh /api/v1/poams"
    echo ""
    echo "  Health: curl http://localhost:8000/api/v1/health"
    echo ""
    echo "  Login:  admin@acme.com / WarlockAdmin2026!"
    echo ""
    echo "  Stop:   kill $API_PID ${OPA_PID:-}"
    echo "============================================================"
else
    echo "ERROR: API server failed to start."
    exit 1
fi
