# Warlock Demo Setup

**Requirements:** Python 3.12+, pip, git. Optional: [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) for policy evaluation.

---

## One Command

```bash
git clone https://github.com/grcwarlock/warlock.git
cd warlock
./scripts/demo.sh
```

That's it. The script:
1. Creates a virtualenv and installs dependencies
2. Starts the OPA server with 670 Rego policies (if OPA is installed)
3. Runs database migrations
4. Seeds 40 connectors, 547+ findings, 29,207 control results across 10 frameworks
5. Starts the API server on port 8000

When it finishes you'll see:

```
============================================================
  Demo is live!
============================================================

  CLI:  warlock coverage
  API:  ./scripts/demo_api.sh
  Health: curl http://localhost:8000/api/v1/health
  Login:  admin@acme.com / WarlockAdmin2026!
============================================================
```

## Or use Make

```bash
make demo
```

## CLI

```bash
warlock coverage                       # compliance summary
warlock findings                       # all findings
warlock results --status non_compliant # non-compliant results
warlock poams                          # POA&M tracking
warlock drift                          # compliance drift
warlock systems                        # system profiles
warlock vendors                        # vendor risk
warlock retention report               # data retention
warlock inheritance --system APP       # control inheritance
warlock remediate <id>                 # show remediation plan (use warlock issues to get IDs)
warlock remediate <id> -a transition --to in_progress
warlock architecture                  # live architecture diagram (terminal)
warlock architecture --format svg     # export as SVG (opens in browser)
```

## API

```bash
./scripts/demo_api.sh                              # coverage
./scripts/demo_api.sh /api/v1/findings?limit=5     # findings
./scripts/demo_api.sh /api/v1/poams                # POA&Ms
./scripts/demo_api.sh /api/v1/drift                # drift
```

## Demo Accounts

| Email | Password | Role |
|---|---|---|
| admin@acme.com | WarlockAdmin2026! | Full admin |
| eve.nakamura@acme.com | SecurityFirst2026! | Auditor (read-only) |
| frank.torres@acme.com | EngineerBuild2026! | System owner (NIST/SOC2/ISO27001) |
| carol.park@acme.com | FinanceReview2026! | Viewer (SOC 2 only) |

## Reset

```bash
./scripts/demo.sh
```

It wipes and re-creates everything from scratch each time.

## Install OPA (optional, recommended)

```bash
brew install opa
```

With OPA installed, the demo evaluates 670 Rego policies across 8 frameworks (NIST 800-53, ISO 27001, SOC 2, CMMC, HIPAA, UCF, Terraform). Without OPA, the demo still works — it just skips policy evaluation.
