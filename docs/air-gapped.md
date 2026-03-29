# Air-Gapped Deployment Guide

Warlock can be deployed in air-gapped (disconnected) environments where there
is no internet access. This guide covers the necessary steps for offline
installation, configuration, and operation.

## Prerequisites

- Python 3.12+ installed on the target system
- All Python wheel files pre-downloaded (see below)
- SQLite 3.35+ (included with Python) or PostgreSQL 14+
- OPA binary (optional, for policy evaluation)

## Step 1: Package Dependencies Offline

On an internet-connected build machine:

```bash
# Clone the repo and download all dependencies as wheels
git clone https://github.com/your-org/warlock.git
cd warlock

# Create a wheels directory with all dependencies
pip download -d ./wheels -e ".[dev]"

# Also download optional AI dependencies if needed
pip download -d ./wheels -e ".[ai]"

# Bundle OPA binary for your target platform
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
```

## Step 2: Transfer to Air-Gapped Environment

Transfer the following to the target system:
- The `warlock/` repository directory
- The `wheels/` directory with all Python packages
- The `opa` binary (if using OPA policy evaluation)

Use approved media transfer procedures (USB, optical disc, etc.) per your
organization's security policy.

## Step 3: Install on Target System

```bash
# Install from local wheels (no internet required)
pip install --no-index --find-links=./wheels -e ".[dev]"

# Verify installation
warlock version

# Place OPA binary in PATH
sudo mv opa /usr/local/bin/
opa version
```

## Step 4: Configure for Offline Operation

Create a `.env` file or set environment variables:

```bash
# Disable AI features (requires internet for API calls)
export WLK_AI_ENABLED=false

# Use SQLite (no external database needed)
export WLK_DATABASE_URL=sqlite:///warlock.db

# Disable external integrations
export WLK_JIRA_ENABLED=false
export WLK_SLACK_ENABLED=false
export WLK_TEAMS_ENABLED=false

# Set security keys (generate offline)
export WLK_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export WLK_ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export WLK_GDPR_HMAC_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# OPA configuration
export WLK_OPA_FAIL_MODE=closed
export WLK_OPA_URL=  # Leave empty to use embedded OPA evaluation
```

## Step 5: Initialize and Seed

```bash
# Initialize the database
warlock init

# Run the demo pipeline with mock connectors (no internet needed)
warlock collect --demo

# Or run the full seed script
WLK_AI_ENABLED=false python scripts/demo_seed.py
```

## Step 6: Verify

```bash
# Check system health
warlock doctor

# Verify data
warlock dashboard posture
warlock findings list
warlock results --limit 10
```

## Connector Configuration for Air-Gapped Environments

In air-gapped deployments, cloud connectors (AWS, Azure, GCP) cannot reach
their APIs. Use these patterns instead:

### File-Based Ingestion

Export security data from connected environments and transfer via approved media:

```bash
# On connected network: export findings
aws securityhub get-findings --output json > findings.json

# Transfer to air-gapped system, then ingest
warlock ingest --source aws --file findings.json
```

### Internal-Only Connectors

These connectors work without internet access:
- **File system scanner** -- scans local filesystems
- **Database connector** -- queries internal databases
- **Syslog receiver** -- receives syslog from internal sources
- **STIX/TAXII** -- if an internal TAXII server is available

## Framework and Policy Updates

To update framework definitions or OPA policies:

1. On the connected build machine, update the repo
2. Transfer only the changed files: `warlock/frameworks/*.yaml`, `policies/`
3. On the air-gapped system:
   ```bash
   # Validate frameworks
   warlock frameworks validate

   # Validate OPA policies
   opa check policies/
   opa test policies/ -v
   ```

## Backup and Recovery

```bash
# SQLite backup (copy the database file)
cp warlock.db warlock.db.backup.$(date +%Y%m%d)

# PostgreSQL backup
pg_dump warlock > warlock_backup_$(date +%Y%m%d).sql
```

## Security Considerations

- Generate all secrets offline using `python3 -c "import secrets; ..."`
- Rotate JWT secrets according to your organization's key rotation policy
- Audit logs are stored in the hash-chained audit trail (database)
- Export audit logs periodically for external archival
- The OPA policy gate defaults to fail-closed -- all requests are denied
  if OPA is configured but unreachable
