# Warlock Demo Setup

**Requirements:** Python 3.12+, Node.js 20+ (for the web UI)

---

## Quick Start

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
make demo
```

This starts the backend (API on port 8000) with seeded demo data. Then open the web UI:

```bash
# In a second terminal:
cd frontend && npm install && npm run dev
```

Open **http://localhost:5173** in your browser.

**Login:** `admin@acme.com` / `WarlockAdmin2026!` (pre-filled)

---

## Web UI

The frontend is a React SPA (Vite + shadcn/ui) that connects to the FastAPI backend. It provides:

| Page | What It Shows | Drill-Down Depth |
|---|---|---|
| **Dashboard** | KPIs, framework heatmap, posture trend, KRIs, drift events | Click any metric → detail |
| **Pipeline** | Connectors → provider → service → resource → finding → remediation | 4 levels |
| **Compliance** | Frameworks → control families → individual control → evidence + assessment | 3 levels |
| **Findings** | Filterable/sortable table of all findings | Click → full detail |
| **Remediation** | POA&Ms, compensating controls, risk acceptances | Lifecycle tracking |
| **Incidents** | Security incidents with timeline and blast radius | Detail + comments |
| **Risk** | Vendor risk scores, Monte Carlo analysis | Score breakdown |
| **Audit** | Engagements, hash-chain audit trail, attestations | Verify chain integrity |
| **Settings** | AI configuration, users, API keys, alerts | Real API key entry |

### AI Configuration

To enable AI-powered remediation and reasoning:

1. Navigate to **Settings → AI Configuration**
2. Select a provider (Anthropic, OpenAI, Gemini, or Ollama)
3. Enter your API key
4. Click **Test Connection**, then **Save**

AI features light up across the platform (remediation suggestions, control explanations, conversational compliance).

### Frontend Development

```bash
make frontend-install   # Install npm dependencies
make frontend-dev       # Start dev server (proxy to API on :8000)
make frontend-build     # Production build
```

---

## CLI

```bash
source .venv/bin/activate       # if using local Python

warlock briefing                       # daily priority view (cross-domain)
warlock briefing -f soc2               # scoped to SOC 2
warlock coverage                       # compliance summary
warlock findings                       # all findings
warlock results --status non_compliant # non-compliant results
warlock control-hub CC6.1 -f soc2      # cross-domain control view
warlock poams                          # POA&M tracking
warlock drift                          # compliance drift
warlock systems                        # system profiles
warlock vendors                        # vendor risk
warlock policy set sla --severity critical --remediation-days 14  # push policy
warlock policy list                    # active policies
warlock retention report               # data retention
warlock lake status                    # data lake zone sizes
warlock lake query "SOC 2 readiness"   # natural language query
warlock ask "are we HIPAA ready?"      # conversational compliance
warlock dashboard                      # interactive TUI dashboard
```

## API

```bash
# Using curl (get a token first)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.com","password":"WarlockAdmin2026!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8000/api/v1/compliance/findings?limit=5 \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Or use the helper script (local Python only)
./scripts/demo_api.sh                              # coverage
./scripts/demo_api.sh /api/v1/findings?limit=5     # findings
./scripts/demo_api.sh /api/v1/poams                # POA&Ms
```

## Demo Accounts

| Email | Password | Role |
|---|---|---|
| admin@acme.com | WarlockAdmin2026! | Full admin |
| eve.nakamura@acme.com | SecurityFirst2026! | Auditor (read-only) |
| frank.torres@acme.com | EngineerBuild2026! | System owner (NIST/SOC2/ISO27001) |
| carol.park@acme.com | FinanceReview2026! | Viewer (SOC 2 only) |

## Install OPA (local Python only)

```bash
brew install opa
```

With OPA installed, the demo evaluates 676 Rego policies across 14 frameworks. Without OPA, it skips policy evaluation.
