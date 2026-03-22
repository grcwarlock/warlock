# Warlock CLI Reference

The Warlock CLI is the primary interface for pipeline operations, compliance monitoring, governance workflows, and system administration.

## Quick Start

```bash
# Activate the virtual environment
source .venv/bin/activate

# Run the full pipeline
warlock collect

# View compliance coverage
warlock coverage

# View findings
warlock findings

# Get help for any command
warlock --help
warlock control --help
```

## Global Options

```
warlock [--verbose/-v] COMMAND [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--verbose`, `-v` | Enable debug logging |

---

## Pipeline Commands

### `warlock init`

Initialize the database (create tables).

```bash
warlock init
```

### `warlock collect`

Run the full pipeline: collect from connectors, normalize, map to controls, assess.

```bash
warlock collect                    # all connectors
warlock collect -s aws             # limit to AWS connector
warlock collect -s aws -s okta     # limit to AWS and Okta
```

| Flag | Description |
|------|-------------|
| `--source`, `-s` | Limit to specific source(s). Can be repeated. |

Output:

```
Pipeline Run
  Raw events collected    191
  Findings normalized     547
  Controls mapped         29,207
  Results assessed        29,207
  Connectors OK           40
  Connectors failed       0
  Duration                6.8s
```

### `warlock ingest`

Ingest a JSON file through the webhook receiver and pipeline.

```bash
warlock ingest -s webhook -p crowdstrike -t falcon_detections --input-file payload.json
```

| Flag | Description |
|------|-------------|
| `--source`, `-s` | Source identifier (required) |
| `--provider`, `-p` | Provider name (required) |
| `--event-type`, `-t` | Event type label (required) |
| `--input-file` | Path to JSON file (required) |

### `warlock scheduler`

Pipeline scheduler for continuous monitoring.

```bash
warlock scheduler start --interval 60    # run every 60 minutes
warlock scheduler status                 # show scheduler state
```

**Subcommands:**

| Command | Description |
|---------|-------------|
| `scheduler start` | Start the scheduler. Blocks until Ctrl+C. |
| `scheduler status` | Show scheduler running state, interval, run count. |

| Flag (start) | Description |
|--------------|-------------|
| `--interval`, `-i` | Interval in minutes between pipeline runs (default: 60) |

---

## Compliance Commands

### `warlock results`

Query control results from the last pipeline run.

```bash
warlock results                                # all results (last 50)
warlock results -f nist_800_53                 # filter by framework
warlock results --status non_compliant         # filter by status
warlock results -n 100                         # show more results
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--status` | Filter: compliant, non_compliant, not_assessed, partial |
| `--limit`, `-n` | Max results (default: 50) |

### `warlock coverage`

Show compliance coverage summary across all frameworks.

```bash
warlock coverage                   # all frameworks
warlock coverage -f soc2           # single framework
warlock coverage --ai              # include AI executive summary
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--ai/--no-ai` | Toggle AI executive summary |

### `warlock control`

Show control detail: status, resources, and remediation guidance.

```bash
warlock control SC-28                        # control across all frameworks
warlock control AC-2 -f nist_800_53          # filter to specific framework
warlock control CC6.1 --no-remediate         # hide remediation section
warlock control SC-28 --ai                   # AI-enhanced remediation commands
warlock control AC-2 --ask                   # interactive AI reasoning session
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--remediate/--no-remediate` | Show/hide remediation guidance (default: show) |
| `--ai/--no-ai` | AI-enhanced per-resource remediation commands |
| `--ask` | Interactive AI reasoning about this control |

### `warlock findings`

Show recent findings from the pipeline.

```bash
warlock findings                                         # list 50 most recent
warlock findings --ask "Which findings are most urgent?"  # ask AI about findings
warlock findings --ask ""                                # start AI REPL for findings
```

| Flag | Description |
|------|-------------|
| `--ask` | Ask AI a question about the listed findings. Empty string opens interactive REPL. |

### `warlock connectors`

List all registered connector types.

```bash
warlock connectors
```

### `warlock sources`

List all registered connectors and normalizers.

```bash
warlock sources
```

---

## Governance Commands

### `warlock issues`

List and manage compliance issues.

```bash
warlock issues                                 # open issues (default excludes closed/verified)
warlock issues -s open -p critical             # critical open issues
warlock issues -f nist_800_53                  # issues for a framework
warlock issues --assigned-to alice@acme.com    # filter by assignee
warlock issues --ask "What should I fix first?" # ask AI about the issues
```

| Flag | Description |
|------|-------------|
| `--status`, `-s` | Filter by status (open, assigned, in_progress, etc.) |
| `--priority`, `-p` | Filter by priority (critical, high, medium, low) |
| `--framework`, `-f` | Filter by framework |
| `--assigned-to` | Filter by assignee email |
| `--limit`, `-n` | Max results (default: 50) |
| `--ask` | Ask AI a question about the listed issues |

### `warlock issues-auto-create`

Auto-create issues from non-compliant control results.

```bash
warlock issues-auto-create                     # all frameworks
warlock issues-auto-create -f soc2             # limit to SOC 2
warlock issues-auto-create --actor ops@acme.com  # custom actor identity
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Limit to a specific framework |
| `--actor` | Actor identity for audit trail (default: cli@warlock, env: WLK_CLI_ACTOR) |

### `warlock remediate`

Show remediation guidance and take action on issues and POA&Ms. Accepts partial UUIDs.

```bash
warlock remediate <id>                                    # show full remediation plan
warlock remediate <id> -a assign --to eve@acme.com        # assign to someone
warlock remediate <id> -a transition --to in_progress     # change status
warlock remediate <id> -a accept-risk --reason "Low risk" # accept the risk
warlock remediate <id> -a extend --to 30 --reason "Delay" # extend POA&M by 30 days
warlock remediate <id> -a comment --reason "Patch staged" # add a comment
warlock remediate <id> --ask "What is the fastest fix?"   # ask AI about the item
warlock remediate <id> --ai                               # AI-enhanced remediation plan
```

| Flag | Description |
|------|-------------|
| `--action`, `-a` | Action: show, assign, transition, accept-risk, extend, comment (default: show) |
| `--to` | Target value (email, status, or days depending on action) |
| `--reason` | Reason or comment text |
| `--ai/--no-ai` | Toggle AI-enhanced remediation guidance |
| `--ask` | Ask AI a question about this item |
| `--actor` | Actor identity for audit trail |

### `warlock poams`

List Plans of Action & Milestones.

```bash
warlock poams                          # all POA&Ms
warlock poams -f fedramp --overdue     # overdue FedRAMP POA&Ms
warlock poams -s in_progress           # filter by status
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--status`, `-s` | Filter by status |
| `--overdue` | Show only overdue POA&Ms |
| `--limit`, `-n` | Max results (default: 50) |

### `warlock compensating-controls`

List compensating controls.

```bash
warlock compensating-controls
warlock compensating-controls -f nist_800_53 -s active
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--status`, `-s` | Filter by status |

### `warlock risk-acceptances`

List risk acceptances.

```bash
warlock risk-acceptances
warlock risk-acceptances --expiring-soon 30    # expiring within 30 days
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--status`, `-s` | Filter by status |
| `--expiring-soon` | Show acceptances expiring within N days |

### `warlock inheritance`

Show control inheritance map for a system.

```bash
warlock inheritance --system FISMA-A
warlock inheritance --system FISMA-A -f nist_800_53
```

| Flag | Description |
|------|-------------|
| `--system` | System profile ID or acronym (required) |
| `--framework`, `-f` | Filter by framework |

### `warlock dependencies`

Show cross-system dependency graph.

```bash
warlock dependencies
warlock dependencies --system <system_id>
```

| Flag | Description |
|------|-------------|
| `--system` | Filter by system profile ID |

---

## Monitoring Commands

### `warlock cadence`

Check monitoring cadence -- are controls being assessed on schedule?

```bash
warlock cadence                    # all controls
warlock cadence -f soc2            # filter by framework
warlock cadence --stale-only       # show only stale controls
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--stale-only` | Show only stale controls |

### `warlock posture-history`

Show posture trends over time per control.

```bash
warlock posture-history -f nist_800_53           # all controls in framework
warlock posture-history -f soc2 -c CC6.1         # specific control
warlock posture-history -f hipaa -d 180           # 180-day window
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Framework to query (required) |
| `--control`, `-c` | Specific control ID |
| `--days`, `-d` | Lookback window in days (default: 90) |

### `warlock sufficiency`

Show evidence sufficiency scores per control.

```bash
warlock sufficiency                    # all frameworks
warlock sufficiency -f soc2            # single framework
warlock sufficiency --below 60         # only controls scoring below 60
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--below` | Show only controls below this sufficiency score |

### `warlock drift`

Show compliance drift events with correlated changes.

```bash
warlock drift                          # last 30 days
warlock drift -d 90                    # last 90 days
warlock drift --direction degraded     # only degradations
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--days`, `-d` | Lookback window in days (default: 30) |
| `--direction` | Filter: improved or degraded |

### `warlock effectiveness`

Show control effectiveness scores over time.

```bash
warlock effectiveness                  # all frameworks, trailing 365 days
warlock effectiveness -f nist_800_53 -d 90
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--days`, `-d` | Trailing window in days (default: 365) |

### `warlock simulate-audit`

Simulate what an auditor would see at a future date.

```bash
warlock simulate-audit -f soc2                         # +90 days (default)
warlock simulate-audit -f nist_800_53 --date 2026-06-15
warlock simulate-audit -f fedramp --system <id> --ai   # AI readiness assessment
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Framework to simulate (required) |
| `--date` | Target audit date, YYYY-MM-DD (default: +90 days) |
| `--system` | System profile ID |
| `--ai/--no-ai` | Toggle AI auditor readiness assessment |

---

## Risk Commands

### `warlock risk analyze`

Run FAIR Monte Carlo risk quantification for a framework.

```bash
warlock risk analyze -f nist_800_53
warlock risk analyze -f soc2 -n 50000 --ai    # 50K iterations + AI narrative
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Framework to analyze (required) |
| `--iterations`, `-n` | Monte Carlo iterations (default: 10000) |
| `--ai/--no-ai` | Toggle AI risk narrative |

### `warlock risk precompute`

Pre-warm the Monte Carlo cache for all active frameworks.

```bash
warlock risk precompute
warlock risk precompute --ttl 8.0    # skip entries fresher than 8 hours
```

| Flag | Description |
|------|-------------|
| `--ttl` | Cache TTL in hours (default: 4.0) |

### `warlock risk cache-stats`

Show Monte Carlo database cache statistics.

```bash
warlock risk cache-stats
```

### `warlock risk invalidate`

Delete cached Monte Carlo entries from the database.

```bash
warlock risk invalidate                       # clear all (with confirmation)
warlock risk invalidate -f nist_800_53        # single framework
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Framework to invalidate (omit for all) |

### `warlock vendors`

Score and monitor vendor risk.

```bash
warlock vendors
warlock vendors -p securityscorecard -t 70    # custom threshold
```

| Flag | Description |
|------|-------------|
| `--provider`, `-p` | Vendor data provider (default: securityscorecard) |
| `--threshold`, `-t` | High-risk threshold, 0-100 (default: 60.0) |

### `warlock policy-coverage`

Check policy documentation coverage for a framework.

```bash
warlock policy-coverage -f nist_800_53
warlock policy-coverage -f soc2 --no-rag      # skip RAG matching
warlock policy-coverage -f hipaa --ai          # AI governance analysis
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Framework to check (required) |
| `--no-rag` | Skip RAG matching, use keyword heuristics only |
| `--ai/--no-ai` | Toggle AI governance analysis |

---

## Admin Commands

### `warlock systems`

List active system profiles.

```bash
warlock systems
```

### `warlock systems-create`

Create a new system profile.

```bash
warlock systems-create -n "Production System" -a PROD --impact high -f nist_800_53 -f soc2
```

| Flag | Description |
|------|-------------|
| `--name`, `-n` | System name (required) |
| `--acronym`, `-a` | System acronym |
| `--description`, `-d` | System description |
| `--impact` | Impact level: low, moderate, high (default: moderate) |
| `--framework`, `-f` | Applicable frameworks (repeatable) |
| `--connector`, `-c` | Connector scope (repeatable) |

### `warlock personnel`

List personnel records with HR/IdP/training cross-reference.

```bash
warlock personnel
warlock personnel -d Engineering --flagged     # flagged engineering personnel
warlock personnel -s terminated                # terminated employees
```

| Flag | Description |
|------|-------------|
| `--department`, `-d` | Filter by department |
| `--status`, `-s` | Filter by HR status (active, terminated, leave) |
| `--flagged` | Show only flagged personnel (risk score > 0) |
| `--limit`, `-n` | Max results (default: 50) |

### `warlock personnel-sync`

Sync personnel records from HR, IdP, and training findings.

```bash
warlock personnel-sync
```

### `warlock retention`

Data retention policies and legal holds.

```bash
warlock retention report                           # show retention report
warlock retention purge                            # dry run
warlock retention purge --execute                  # actually delete
warlock retention purge --execute -f hipaa         # purge only HIPAA-retained records
```

| Subcommand | Description |
|------------|-------------|
| `retention report` | Show retention report: record ages, purgeable counts, legal holds, framework retention periods. |
| `retention purge` | Purge records past their retention period. Dry run by default. |

| Flag (purge) | Description |
|--------------|-------------|
| `--dry-run/--execute` | Dry run (default) or actually delete |
| `--framework`, `-f` | Limit to a specific framework's retention period |

### `warlock data-silos`

List discovered data silos.

```bash
warlock data-silos
warlock data-silos --type s3_bucket -c restricted
```

| Flag | Description |
|------|-------------|
| `--type` | Filter by silo type (s3_bucket, rds_database, etc.) |
| `--classification`, `-c` | Filter by classification |
| `--provider`, `-p` | Filter by cloud provider |
| `--limit`, `-n` | Max results (default: 50) |

### `warlock data-silos-discover`

Auto-discover data silos from findings.

```bash
warlock data-silos-discover
```

### `warlock questionnaires`

List vendor questionnaires.

```bash
warlock questionnaires
warlock questionnaires -s completed -v "Vendor Inc"
```

| Flag | Description |
|------|-------------|
| `--status`, `-s` | Filter by status |
| `--vendor`, `-v` | Filter by vendor name |
| `--limit`, `-n` | Max results (default: 50) |

### `warlock questionnaires-seed`

Seed default questionnaire templates (SIG Lite, DDQ).

```bash
warlock questionnaires-seed
```

---

## Export Commands

### `warlock oscal`

Export assessment data in OSCAL JSON format.

```bash
warlock oscal                                              # assessment results, all frameworks
warlock oscal -f nist_800_53 --format ssp -o ssp.json      # system security plan
warlock oscal -f soc2 --format poam --ai                   # POA&M with AI narratives
```

| Flag | Description |
|------|-------------|
| `--framework`, `-f` | Filter by framework |
| `--system-name`, `-s` | System name for OSCAL metadata (default: "Warlock GRC System") |
| `--output`, `-o` | Output file path (default: auto-generated in exports/) |
| `--format` | OSCAL document type: ar, ssp, poam (default: ar) |
| `--description` | System description (for SSP) |
| `--ai/--no-ai` | Use AI to generate framework-aware narratives (SSP/POA&M) |

### `warlock framework-diff`

Compare two framework versions and show control changes.

```bash
warlock framework-diff --old old_nist.yaml --new new_nist.yaml
```

| Flag | Description |
|------|-------------|
| `--old` | Path to old framework YAML (required) |
| `--new` | Path to new framework YAML (required) |

### `warlock architecture`

Render a live architecture diagram from the seeded database.

```bash
warlock architecture                       # rich terminal tree
warlock architecture --format svg -o arch.svg   # SVG (requires d2)
warlock architecture --format png -o arch.png   # PNG (requires d2)
```

| Flag | Description |
|------|-------------|
| `--format` | Output format: terminal, svg, png (default: terminal) |
| `--output`, `-o` | Output file path (for svg/png) |

---

## AI Commands

### `warlock ai status`

Show AI service status: provider, model, availability.

```bash
warlock ai status
```

### `warlock ai models`

List available models for the configured provider.

```bash
warlock ai models
```

### `warlock ai configure`

Configure the AI provider -- discover models and validate connectivity.

```bash
warlock ai configure -p ollama -m qwen3-coder:30b -u http://localhost:11434
warlock ai configure -p anthropic -k sk-ant-...
warlock ai configure -p openai
```

| Flag | Description |
|------|-------------|
| `--provider`, `-p` | AI provider: anthropic, openai, gemini, ollama (required) |
| `--api-key`, `-k` | API key (or set WLK_AI_API_KEY) |
| `--model`, `-m` | Model to use (omit to see available models) |
| `--base-url`, `-u` | Base URL (for Ollama/vLLM) |

### `warlock ai test`

Send a test prompt to verify the AI provider is working.

```bash
warlock ai test
warlock ai test -p "Summarize NIST 800-53 AC-2 in one sentence."
```

| Flag | Description |
|------|-------------|
| `--prompt`, `-p` | Test prompt to send |

### `warlock ask`

Ask a compliance question (queries the data lake).

```bash
warlock ask "What controls are failing for NIST 800-53?"
```

Requires `WLK_LAKE_ENABLED=true`.

---

## Data Lake Commands

### `warlock lake init`

Create lake directory structure (raw/enrichment/curated zones).

```bash
warlock lake init
warlock lake init --path /data/lake
```

### `warlock lake status`

Show lake status: zones, file counts, total size.

```bash
warlock lake status
```

---

## Command Summary

| Group | Commands |
|-------|----------|
| Pipeline | `init`, `collect`, `ingest`, `scheduler start/status` |
| Compliance | `results`, `coverage`, `control`, `findings`, `connectors`, `sources` |
| Governance | `issues`, `issues-auto-create`, `remediate`, `poams`, `compensating-controls`, `risk-acceptances`, `inheritance`, `dependencies` |
| Monitoring | `cadence`, `posture-history`, `sufficiency`, `drift`, `effectiveness`, `simulate-audit` |
| Risk | `risk analyze/precompute/cache-stats/invalidate`, `vendors`, `policy-coverage` |
| Admin | `systems`, `systems-create`, `personnel`, `personnel-sync`, `retention report/purge`, `data-silos`, `data-silos-discover`, `questionnaires`, `questionnaires-seed` |
| Export | `oscal`, `framework-diff`, `architecture` |
| AI | `ai status/models/configure/test`, `ask` |
| Lake | `lake init/status` |
