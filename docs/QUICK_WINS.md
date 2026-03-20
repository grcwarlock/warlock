# Documentation Quick Wins — Easy Fixes This Week

**Effort:** 1-2 hours total
**Impact:** High (fixes inaccuracies, improves credibility, unblocks developers)

These are changes you can make today that improve documentation quality and discoverability without writing 50 new pages.

---

## 1. Fix Accuracy Issues (15 minutes)

### Issue #1: Normalizer Count Off by 1

**File:** `README.md` line 8
**Current:** `Stage 2: Normalizers (41 parsers) → FindingData`
**Should be:** `Stage 2: Normalizers (40 parsers) → FindingData`

**Why it matters:** Audit report identifies 40 normalizers. Having wrong numbers damages credibility with enterprises.

**Fix:**
```bash
# In README.md, line 8:
# OLD: Stage 2: Normalizers (41 parsers) → FindingData
# NEW: Stage 2: Normalizers (40 parsers) → FindingData
```

**Time:** 1 minute

---

### Issue #2: OPA Policy Count Off by 24

**File:** `DEMO.md` line 17
**Current:** `Starts the OPA server with 616 Rego policies`
**Actual:** Audit report says 592 policies

**Verify first:**
```bash
find /Users/jsn/Coding/GitHub/warlock/policies -name "*.rego" | wc -l
```

**Fix** (after verification):
```bash
# In DEMO.md, line 17:
# OLD: Starts the OPA server with 616 Rego policies
# NEW: Starts the OPA server with 592 Rego policies
```

**Time:** 5 minutes (including verification)

---

### Issue #3: Verify Test Count in CLAUDE.md

**File:** `CLAUDE.md` line 77
**Current:** `**190 tests, 9 files**`

**Verify actual count:**
```bash
cd /Users/jsn/Coding/GitHub/warlock
.venv/bin/pytest --collect-only -q 2>&1 | tail -1
```

**If different, fix:**
```bash
# In CLAUDE.md, line 77:
# Update the hardcoded test count to match actual
```

**Time:** 5 minutes

---

## 2. Create Essential Index Files (30 minutes)

These files act as navigation and quick reference. They don't require deep content yet — just structure and links.

### docs/API_QUICK_START.md

**Create:** `/Users/jsn/Coding/GitHub/warlock/docs/API_QUICK_START.md`

```markdown
# REST API Quick Start

## Authentication

Get a JWT token:
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.com","password":"WarlockAdmin2026!"}'
```

Use it in requests:
```bash
curl http://localhost:8000/api/v1/results \
  -H "Authorization: Bearer <TOKEN>"
```

## Common Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/health` | Health check |
| `GET /api/v1/results` | Control results |
| `GET /api/v1/findings` | Normalized findings |
| `GET /api/v1/coverage` | Compliance summary |
| `POST /api/v1/pipeline/collect` | Trigger collection |

See [Full API Reference](#) for complete documentation.

## Tutorials

- [Building a Frontend Dashboard](#)
- [Integrating with Slack](#)
- [Custom Reporting](#)

## See Also

- [API_REFERENCE.md](#) — Complete endpoint documentation
- [API_AUTH_GUIDE.md](#) — Authentication details
- [API_ERRORS.md](#) — Error handling
```

**Time:** 10 minutes

---

### docs/FRAMEWORKS_INDEX.md

**Create:** `/Users/jsn/Coding/GitHub/warlock/docs/FRAMEWORKS_INDEX.md`

```markdown
# Compliance Frameworks — Index

Warlock supports 10 compliance frameworks with 1,779 controls.

## Quick Links by Framework

| Framework | Controls | Audit | Guide |
|-----------|----------|-------|-------|
| **NIST 800-53** | 1,176 | Yes | [Coming] |
| **ISO 27001** | 93 | Yes | [Coming] |
| **SOC 2 (TSC)** | 46 | Yes | [Coming] |
| **HIPAA Security Rule** | 64 | Yes | [Coming] |
| **CMMC Level 2** | 110 | Yes | [Coming] |
| **ISO 27701** | 95 | Yes | [Coming] |
| **FedRAMP Moderate** | 26 | Yes | [Coming] |
| **ISO 42001** | 39 | Yes | [Coming] |
| **UCF (Unified)** | 115 | Yes | [Coming] |
| **GDPR** | 15 | Yes | [Coming] |

## What Does Each Framework Require?

### I'm being audited for...

- **SOC 2 Type II** → [SOC 2 Roadmap](#)
- **ISO 27001** → [ISO 27001 Guide](#)
- **NIST 800-53 Moderate** → [NIST Implementation](#)
- **HIPAA** → [HIPAA Guide](#)
- **CMMC Level 2** → [CMMC Roadmap](#)

## Common Questions

- [Which controls apply to me?](#)
- [What evidence do I need?](#)
- [Can I use compensating controls?](#)
- [How long do I need to keep records?](#)
```

**Time:** 10 minutes

---

### docs/CONNECTORS_INDEX.md

**Create:** `/Users/jsn/Coding/GitHub/warlock/docs/CONNECTORS_INDEX.md`

```markdown
# Connector Configuration Index

Warlock connects to 40 data sources across 16 categories.

## Quick Setup by Category

### Cloud Providers (10)
- [AWS](./connectors/AWS_CONNECTOR_GUIDE.md) — [Coming] ✅
- [Azure](./connectors/AZURE_CONNECTOR_GUIDE.md) — [Coming]
- [GCP](./connectors/GCP_CONNECTOR_GUIDE.md) — [Coming] ✅
- [OCI](./connectors/OCI_CONNECTOR_GUIDE.md) — [Coming]
- [IBM Cloud](./connectors/IBM_CLOUD_CONNECTOR_GUIDE.md) — [Coming]
- Alibaba, DigitalOcean, Huawei, OVH, Cloudflare — [Coming]

### Identity & Access (5)
- [Okta](./connectors/OKTA_CONNECTOR_GUIDE.md) — [Coming] ✅
- [Entra ID](./connectors/ENTRA_ID_CONNECTOR_GUIDE.md) — [Coming]
- CyberArk, SailPoint, HashiCorp Vault — [Coming]

### Security Scanning (3)
- [Tenable](./connectors/TENABLE_CONNECTOR_GUIDE.md) — [Coming]
- [Qualys](./connectors/QUALYS_CONNECTOR_GUIDE.md) — [Coming]
- [Wiz](./connectors/WIZ_CONNECTOR_GUIDE.md) — [Coming]

### SIEM & EDR (6)
- [CrowdStrike](./connectors/CROWDSTRIKE_CONNECTOR_GUIDE.md) — [Coming]
- Defender, SentinelOne, Sentinel, Splunk, Elastic — [Coming]

### Enterprise Apps (5)
- [Workday](./connectors/WORKDAY_CONNECTOR_GUIDE.md) — [Coming]
- ServiceNow, Confluence, KnowBe4, OneTrust — [Coming]

### Other (6)
- Prisma Cloud, Veeam, Intune, Proofpoint, Verkada, MLflow — [Coming]

## Common Setup Questions

- [How do I generate API credentials?](#)
- [What permissions do I need?](#)
- [How often does data get collected?](#)
- [What data does this connector see?](#)
- [Troubleshooting: Connector not collecting](#)

✅ = Guide created | [Coming] = In progress
```

**Time:** 10 minutes

---

## 3. Create Searchable Command Reference (20 minutes)

**File:** Create `/Users/jsn/Coding/GitHub/warlock/docs/CLI_COMMAND_REFERENCE.md`

Extract commands from code and create a simple table that's searchable:

```markdown
# CLI Command Reference

Quick lookup for all Warlock CLI commands.

## Pipeline & Collection

| Command | Purpose | Example |
|---------|---------|---------|
| `collect` | Run full pipeline | `warlock collect` |
| `collect -s aws` | Collect from one source | `warlock collect -s aws` |
| `scheduler start` | Start continuous collection | `warlock scheduler start` |
| `scheduler status` | Check scheduler | `warlock scheduler status` |

## Compliance Results

| Command | Purpose | Example |
|---------|---------|---------|
| `results` | Show control results | `warlock results` |
| `results -f nist_800_53` | Filter by framework | `warlock results -f nist_800_53` |
| `coverage` | Compliance summary | `warlock coverage` |
| `findings` | Show normalized findings | `warlock findings` |
| `drift` | Compliance drift events | `warlock drift` |

## Remediation

| Command | Purpose | Example |
|---------|---------|---------|
| `issues` | List compliance issues | `warlock issues` |
| `poams` | List POA&Ms | `warlock poams` |
| `poams --overdue` | Show overdue items | `warlock poams --overdue` |
| `remediate <id>` | Get remediation plan | `warlock remediate abc123` |
| `compensating-controls` | List compensating controls | `warlock compensating-controls` |

## Systems & Architecture

| Command | Purpose | Example |
|---------|---------|---------|
| `systems` | List system profiles | `warlock systems` |
| `systems-create` | Create new system | `warlock systems-create --name "API"` |
| `inheritance --system <id>` | Control inheritance | `warlock inheritance --system API` |
| `dependencies` | Cross-system dependencies | `warlock dependencies` |
| `architecture` | Visual architecture | `warlock architecture` |

## Analysis & Assessment

| Command | Purpose | Example |
|---------|---------|---------|
| `cadence` | Monitoring cadence | `warlock cadence` |
| `sufficiency` | Evidence sufficiency | `warlock sufficiency` |
| `effectiveness` | Control effectiveness | `warlock effectiveness` |
| `simulate-audit --date 2026-06-01` | Project audit readiness | `warlock simulate-audit --date 2026-06-01` |
| `risk` | Risk quantification (FAIR) | `warlock risk` |

## Export & Reporting

| Command | Purpose | Example |
|---------|---------|---------|
| `oscal` | Export OSCAL JSON | `warlock oscal` |
| `export binder --engagement <id>` | Audit evidence package | `warlock export binder` |
| `framework-diff` | Compare framework versions | `warlock framework-diff --old v5 --new v6` |
| `vendors` | Vendor risk scores | `warlock vendors` |

## Administration

| Command | Purpose | Example |
|---------|---------|---------|
| `personnel` | List personnel | `warlock personnel` |
| `personnel-sync` | Sync from Workday | `warlock personnel-sync` |
| `questionnaires` | List questionnaires | `warlock questionnaires` |
| `data-silos` | List data silos | `warlock data-silos` |
| `retention report` | Retention status | `warlock retention report` |
| `retention purge --execute` | Purge old records | `warlock retention purge --execute` |

## Get Help

```bash
warlock --help                # List all commands
warlock <command> --help      # Help for specific command
warlock --verbose             # Enable debug logging
```
```

**Time:** 20 minutes

---

## 4. Link Everything from README (10 minutes)

Update README.md to add section linking to all new docs:

**Add to bottom of README.md (before License):**

```markdown
## Documentation

Comprehensive guides for users, developers, and operators:

**Getting Started:**
- **[Quick Demo](DEMO.md)** — Set up in 5 minutes
- **[API Quick Start](docs/API_QUICK_START.md)** — Connect to the API
- **[CLI Command Reference](docs/CLI_COMMAND_REFERENCE.md)** — All CLI commands

**Integration:**
- **[Frameworks Index](docs/FRAMEWORKS_INDEX.md)** — Map to compliance requirements
- **[Connectors Index](docs/CONNECTORS_INDEX.md)** — Configure data sources

**Production:**
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** — Deploy to AWS/Azure/GCP (Coming soon)
- **[Operations & Runbooks](docs/operations/)** — Backup, recovery, troubleshooting

**Development:**
- **[Developer Setup](docs/developer/DEVELOPER_SETUP.md)** — Set up dev environment (Coming soon)
- **[Contributing](CONTRIBUTING.md)** — How to submit PRs (Coming soon)

**Full Documentation:**
- [API Reference](docs/api/API_REFERENCE.md) (Coming soon)
- [Security Architecture](docs/security/SECURITY_ARCHITECTURE.md) (Coming soon)
- [Architecture Decisions](docs/architecture/ARCHITECTURE_DECISIONS.md) (Coming soon)

**Audit & Compliance:**
- [NIST 800-53 Implementation](docs/frameworks/NIST_800_53_IMPLEMENTATION.md) (Coming soon)
- [SOC 2 Type II Roadmap](docs/frameworks/SOC2_TYPE_II_ROADMAP.md) (Coming soon)
- [ISO 27001 Guide](docs/frameworks/ISO_27001_IMPLEMENTATION.md) (Coming soon)
```

**Time:** 10 minutes

---

## 5. Create .github Issue Templates (15 minutes)

Create issue templates so contributors follow a standard format.

**Create:** `/.github/ISSUE_TEMPLATE/bug_report.md`

```markdown
---
name: Bug Report
about: Report a problem
labels: bug
---

## Description

Brief description of the bug.

## Steps to Reproduce

1. ...
2. ...

## Expected Behavior

What should happen.

## Actual Behavior

What actually happened.

## Environment

- Warlock version: (e.g., v2.0.0a1)
- OS: (e.g., macOS, Linux, Windows)
- Python version: (e.g., 3.12.1)
- Database: (e.g., PostgreSQL 15, SQLite)

## Logs

```
Paste error logs here
```

## Additional Context

Any other context.
```

**Create:** `/.github/ISSUE_TEMPLATE/feature_request.md`

```markdown
---
name: Feature Request
about: Suggest an idea
labels: enhancement
---

## Is this related to a problem?

Describe the problem (optional).

## Description

Clear description of the feature.

## Why is this useful?

Who benefits? What problem does it solve?

## Proposed Implementation

How might this work? (optional)

## Alternatives

Other ways to solve this? (optional)
```

**Create:** `/.github/ISSUE_TEMPLATE/documentation.md`

```markdown
---
name: Documentation Issue
about: Report missing or incorrect documentation
labels: documentation
---

## What's the Issue?

- [ ] Missing documentation
- [ ] Incorrect documentation
- [ ] Unclear documentation
- [ ] Broken links

## Which Document?

Link or describe the document that needs work.

## What's Wrong?

Describe the problem.

## Suggested Fix (if applicable)

How should it be fixed?
```

**Time:** 15 minutes

---

## 6. Update docs/TODO.md (5 minutes)

The existing TODO.md is outdated. Update it to reference the new comprehensive documentation checklist:

**Replace content of `/docs/TODO.md` with:**

```markdown
# Warlock TODO — Comprehensive Tracker

See [DOCUMENTATION_TODO.md](DOCUMENTATION_TODO.md) for complete documentation enhancement roadmap.

See [QUICK_WINS.md](QUICK_WINS.md) for quick fixes this week.

---

## Critical Bugs (From Audit Report)

See [audit-report-2026-03-19.md](audit-report-2026-03-19.md) for 106 findings.

### Top 10 Critical Issues

1. ABAC scope filters not wired (data exposure)
2. ZIP path traversal in binder.py
3. Assertion bindings overwrite (AC-2, AT-2 broken)
4. OPA policies dead code (no evaluation engine)
5. OSCAL exporter disconnected from packages
6. CLI _resolve_system_id("") matches all systems
7. Terraform: S3 audit logs missing lifecycle
8. Terraform: CloudTrail missing KMS key
9. Datetime naive/aware bugs (6 locations)
10. Pipeline no concurrency protection

See audit-report for all 106 findings and priority fix plan.

---

## Documentation Status

### P0 (Blocking Adoption) — In Progress

- [ ] API Reference & auth guide
- [ ] Deployment guide
- [ ] CLI reference
- [ ] Contributing guide
- [ ] Accuracy fixes

### P1 (High Value) — Queued

- [ ] Framework implementation guides (NIST, SOC 2, ISO)
- [ ] Connector integration guides
- [ ] Operations runbooks
- [ ] Monitoring & alerting guide

### P2 (Polish) — Backlog

- [ ] Changelog
- [ ] Architecture decision records
- [ ] Security whitepaper

---

## Operations Quality

**Medium Priority** (from original TODO):

- [ ] DEPLOYMENT_GUIDE.md — Port and update 765-line v1 guide
- [ ] CHANGELOG.md — Create release history
- [ ] CONTRIBUTING.md — Contribution guidelines
- [ ] Crosswalks with confidence scores — v1 metadata missing
- [ ] Framework event_types wiring — FedRAMP/HIPAA/CMMC/GDPR need checks

**Low Priority:**

- [ ] demo_exports/ — Pre-generated sample packages
- [ ] Architecture diagram HTML
- [ ] Celery integration
- [ ] nltk CVE remediation

---

**Status:** Documentation roadmap created, implementation starting
**Next Review:** 2026-03-26 (weekly)
```

**Time:** 5 minutes

---

## Summary: What You Get in 2 Hours

| Task | Time | Impact |
|------|------|--------|
| Fix accuracy issues | 15 min | ✅ Credibility |
| Create index files (API, Frameworks, Connectors) | 30 min | ✅ Navigation |
| CLI command reference | 20 min | ✅ Discoverability |
| Link from README | 10 min | ✅ Visibility |
| GitHub issue templates | 15 min | ✅ Contributor experience |
| Update TODO.md | 5 min | ✅ Project clarity |
| **TOTAL** | **1 hour 35 min** | **High ROI** |

---

## Execution Plan

**Day 1 (1 hour):**
1. Fix accuracy issues (15 min)
2. Create index files (30 min)
3. Update README with links (10 min)
4. Update TODO.md (5 min)

**Day 2 (1 hour):**
5. Create CLI reference (20 min)
6. Create GitHub issue templates (15 min)
7. Review and test links (25 min)

**Output:**
- 5 new reference docs
- 3 GitHub templates
- Fixed inaccuracies
- Better navigation
- Improved contributor experience

---

**Estimated PR size:** 20 files changed, ~2,000 lines added
**Ready to commit after:** Manual link check (5 min)
