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
    echo "[1/7] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/7] Virtual environment exists."
fi
source .venv/bin/activate

# 2. Install
echo "[2/7] Installing dependencies..."
pip install -e ".[dev,ai]" --quiet 2>/dev/null

# 3. Kill anything on our ports
echo "[3/7] Clearing ports..."
lsof -ti:8000 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti:8181 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# 4. Start OPA server with policy bundle
if command -v opa &>/dev/null; then
    echo "[4/7] Starting OPA server (port 8181)..."
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
    echo "[4/7] OPA not installed — skipping policy evaluation"
    echo "       Install with: brew install opa"
fi

# 5. Fresh database + seed (AI disabled for speed)
echo "[5/7] Seeding demo environment..."
rm -f warlock.db
export WLK_AI_ENABLED=false
alembic upgrade head 2>&1 | grep -v "^INFO" || true
python scripts/demo_seed.py 2>&1 | grep -E "^\[|^  Raw|^  Find|^  Cont|^  Conn|^  Dur|Seed complete" || true
echo ""

# 6. AI configuration prompt
echo "[6/7] AI Reasoning (optional)"
echo ""
echo "  Warlock supports AI-powered compliance reasoning."
echo "  Press Enter at any prompt to skip and run in deterministic mode."
echo ""
echo "  Providers: 1) Anthropic  2) OpenAI  3) Ollama  4) Gemini"
printf "  Provider [1-4] (Enter to skip): "
read -r AI_CHOICE
if [ -n "$AI_CHOICE" ]; then
    case "$AI_CHOICE" in
        1|anthropic|Anthropic)
            export WLK_AI_PROVIDER=anthropic
            DEFAULT_MODEL="claude-sonnet-4-20250514"
            export WLK_AI_BASE_URL=""
            ;;
        2|openai|OpenAI)
            export WLK_AI_PROVIDER=openai
            DEFAULT_MODEL="gpt-4o"
            export WLK_AI_BASE_URL=""
            ;;
        3|ollama|Ollama)
            export WLK_AI_PROVIDER=ollama
            DEFAULT_MODEL="qwen3-coder:30b"
            export WLK_AI_BASE_URL="https://ollama.com"
            ;;
        4|gemini|Gemini)
            export WLK_AI_PROVIDER=gemini
            DEFAULT_MODEL="gemini-2.0-flash"
            export WLK_AI_BASE_URL=""
            ;;
        *)
            echo "       Unknown provider. Skipping AI."
            export WLK_AI_ENABLED=false
            DEFAULT_MODEL=""
            ;;
    esac

    if [ "$WLK_AI_ENABLED" != "false" ]; then
        printf "  API Key: "
        read -r AI_KEY
        if [ -n "$AI_KEY" ]; then
            export WLK_AI_API_KEY="$AI_KEY"
            printf "  Model [${DEFAULT_MODEL}]: "
            read -r AI_MODEL
            export WLK_AI_MODEL="${AI_MODEL:-$DEFAULT_MODEL}"
            export WLK_AI_ENABLED=true
            echo ""
            echo "       AI enabled: ${WLK_AI_PROVIDER}/${WLK_AI_MODEL}"
            echo "       Use --ai flag on commands: warlock coverage --ai"
            echo "       Interactive reasoning:     warlock remediate <id> --ask"
        else
            echo "       No API key provided. Skipping AI."
            export WLK_AI_ENABLED=false
        fi
    fi
else
    export WLK_AI_ENABLED=false
    echo ""
    echo "       Running in deterministic mode (no AI). You can enable later:"
    echo "       export WLK_AI_PROVIDER=anthropic WLK_AI_API_KEY=<key> WLK_AI_MODEL=claude-sonnet-4-20250514 WLK_AI_ENABLED=true"
fi
echo ""

# 7. Start API server
echo "[7/7] Starting API server (port 8000)..."
warlock-api &>/dev/null &
API_PID=$!
sleep 2

if kill -0 $API_PID 2>/dev/null; then
    echo ""
    echo "============================================================"
    echo "  Demo is live!"
    echo "============================================================"
    echo ""
    echo "  >>> source .venv/bin/activate <<<"
    echo "  (run this first to enable CLI commands)"
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
    echo "  TUI:  warlock dashboard              # interactive dashboard"
    echo "        warlock tui                     # command browser"
    echo ""
    echo "  API (100+ endpoints — use ./scripts/demo_api.sh <path>):"
    echo ""
    echo "    Compliance:"
    echo "        ./scripts/demo_api.sh                                # coverage"
    echo "        ./scripts/demo_api.sh /api/v1/findings?limit=10     # findings"
    echo "        ./scripts/demo_api.sh /api/v1/results?status=non_compliant"
    echo "        ./scripts/demo_api.sh /api/v1/drift                 # compliance drift"
    echo "        ./scripts/demo_api.sh /api/v1/cadence               # monitoring cadence"
    echo "        ./scripts/demo_api.sh /api/v1/sufficiency           # evidence gaps"
    echo "        ./scripts/demo_api.sh /api/v1/effectiveness         # control effectiveness"
    echo "        ./scripts/demo_api.sh /api/v1/posture/history?framework=nist_800_53"
    echo ""
    echo "    Remediation:"
    echo "        ./scripts/demo_api.sh /api/v1/poams                 # POA&Ms"
    echo "        ./scripts/demo_api.sh /api/v1/compensating-controls"
    echo "        ./scripts/demo_api.sh /api/v1/risk-acceptances"
    echo "        ./scripts/demo_api.sh /api/v1/issues?limit=10"
    echo ""
    echo "    Assets & People:"
    echo "        ./scripts/demo_api.sh /api/v1/systems               # system profiles"
    echo "        ./scripts/demo_api.sh /api/v1/personnel?limit=10"
    echo "        ./scripts/demo_api.sh /api/v1/data-silos"
    echo "        ./scripts/demo_api.sh /api/v1/vendors/risk          # vendor scores"
    echo "        ./scripts/demo_api.sh /api/v1/questionnaires"
    echo ""
    echo "    Audit & Export:"
    echo "        ./scripts/demo_api.sh /api/v1/engagements           # audit engagements"
    echo "        ./scripts/demo_api.sh /api/v1/retention/report"
    echo "        ./scripts/demo_api.sh /api/v1/audit-trail"
    echo "        ./scripts/demo_api.sh /api/v1/frameworks"
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
