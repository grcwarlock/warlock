# Warlock Demo Setup

Step-by-step instructions to provision and run a fully operational demo environment.

**Requirements:** Python 3.12+, pip, git

---

## Step 1: Clone and Install

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,ai]"
```

## Step 2: Initialize and Seed

```bash
alembic upgrade head
python scripts/demo_seed.py
```

This takes ~7 seconds. When it finishes you'll see:

```
Connectors succeeded:   40
Connectors failed:      0
Raw events collected:   191
Findings normalized:    547
Controls mapped:        26,135
```

Your database (`warlock.db`) is now populated with 26,135 control results across 6 compliance frameworks from 40 connectors.

## Step 3: Try the CLI

```bash
warlock coverage
warlock findings
warlock results --status non_compliant
warlock poams
warlock drift
warlock systems
warlock vendors
warlock issues
```

## Step 4: Start the API Server

Open a new terminal tab (`Cmd+T`):

```bash
cd /Users/jsn/Coding/GitHub/warlock
source .venv/bin/activate
warlock-api
```

The API starts at **http://localhost:8000**.

If you get `address already in use`, kill the old process first:

```bash
lsof -ti:8000 | xargs kill -9
warlock-api
```

Verify it's running:

```bash
curl http://localhost:8000/api/v1/health
```

## Step 5: Authenticate

Use the helper script (handles token automatically):

```bash
./scripts/demo_api.sh                              # compliance coverage
./scripts/demo_api.sh /api/v1/findings?limit=5     # findings
./scripts/demo_api.sh /api/v1/poams                # POA&Ms
./scripts/demo_api.sh /api/v1/drift                # compliance drift
```

Or do it manually:

```bash
# Get a token (paste this as ONE line)
export TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@acme.com","password":"WarlockAdmin2026!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Query any endpoint
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/results/coverage | python3 -m json.tool
```

## Demo Accounts

| Email | Password | Role |
|---|---|---|
| admin@acme.com | WarlockAdmin2026! | Full admin access |
| eve.nakamura@acme.com | SecurityFirst2026! | Auditor (read-only) |
| frank.torres@acme.com | EngineerBuild2026! | System owner (scoped to NIST/SOC2/ISO27001) |
| carol.park@acme.com | FinanceReview2026! | Viewer (SOC 2 only) |

## Reset

To wipe and re-seed from scratch:

```bash
rm -f warlock.db
alembic upgrade head
python scripts/demo_seed.py
```

## What's in the Demo

- **40 connectors** — AWS, Azure, GCP, Okta, CrowdStrike, Defender, Sentinel, Splunk, Tenable, Snyk, GitHub, ServiceNow, and 28 more
- **6 frameworks** — NIST 800-53, ISO 27001, ISO 27701, ISO 42001, SOC 2, UCF
- **547+ findings** with both compliant and non-compliant results
- **25 deterministic assertions** all exercised
- **5 system profiles** with FIPS 199 categorization
- **18 POA&Ms**, 10 compensating controls, 7 risk acceptances
- **50 personnel** with MFA status, training flags, risk scores
- **30 days** of posture snapshots, drift events, and change history
- **2 audit engagements** with external auditors and evidence requests
