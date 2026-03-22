# Warlock GRC API Reference

Base URL: `/api/v1`

Interactive docs: `/docs` (Swagger UI) | `/redoc` (ReDoc)

## Authentication

All endpoints except Health and Trust Portal require authentication via one of:

- **JWT Bearer Token** -- Obtain via `POST /api/v1/auth/login`, pass as `Authorization: Bearer <token>`
- **API Key** -- Create via `POST /api/v1/auth/api-keys`, pass as `X-Api-Key: <key>`

API keys are scoped. A read-only API key on an admin account only grants read access (intersection of role permissions and key scopes).

### Roles and Permissions

| Role    | Permissions |
|---------|-------------|
| viewer  | read |
| analyst | read, export |
| operator | read, write, export, run_pipeline |
| admin   | read, write, export, run_pipeline, manage_users, manage_keys |
| owner   | all permissions |

### ABAC Scoping

Users can be restricted to specific frameworks (`allowed_frameworks`) and data sources (`allowed_sources`). API responses are automatically filtered to the user's allowed scope.

### Rate Limits

Per-endpoint rate limits are enforced by middleware. Sensitive endpoints have stricter limits:

| Endpoint | Requests/min | Burst |
|----------|-------------|-------|
| `POST /auth/login` | 10 | 5 |
| `POST /auth/register` | 5 | 2 |
| `POST /pipeline/collect` | 5 | 2 |
| `POST /risk/analyze` | 10 | 2 |
| `POST /ai/reason` | 30 | 5 |
| `POST /ai/converse` | 30 | 5 |
| All other endpoints | 60 | 10 |

### Request Size Limit

Maximum request body: 10 MB. Requests exceeding this return `413 Request Entity Too Large`.

---

## Error Format

All errors follow this structure:

```json
{
  "detail": "Human-readable error message"
}
```

Common status codes:

| Code | Meaning |
|------|---------|
| 400 | Bad request -- invalid parameters or body |
| 401 | Unauthorized -- missing or invalid credentials |
| 403 | Forbidden -- ABAC scope violation or insufficient permissions |
| 404 | Not found |
| 409 | Conflict -- resource already exists or pipeline already running |
| 413 | Request body too large (>10 MB) |
| 429 | Rate limited |
| 503 | Service unavailable -- AI not configured, OPA down |

---

## Pagination

Paginated endpoints accept `limit` and `offset` query parameters and return:

```json
{
  "items": [...],
  "total": 1250,
  "limit": 50,
  "offset": 0
}
```

Default `limit` is 50. Maximum is 1000.

---

## Health (3 endpoints) -- No Auth Required

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Basic health check. Returns version and timestamp. |
| GET | `/health/live` | Liveness probe. Returns `{"status": "ok"}` if the process is alive. |
| GET | `/health/ready` | Readiness probe. Checks database connectivity and scheduler state. Returns 503 if degraded. |

**Readiness response:**

```json
{
  "status": "ok",
  "checks": {
    "database": "ok",
    "scheduler": "running"
  },
  "timestamp": "2026-03-21T00:00:00+00:00"
}
```

---

## Auth (9 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| POST | `/auth/login` | No | -- | Authenticate with email/password. Returns JWT tokens or MFA challenge. |
| POST | `/auth/mfa/verify` | No | -- | Complete MFA login with TOTP code. Returns JWT tokens. |
| POST | `/auth/refresh` | No | -- | Exchange refresh token for new access + refresh token pair. |
| POST | `/auth/register` | Yes | manage_users | Create a new user account. |
| POST | `/auth/api-keys` | Yes | manage_keys | Create a scoped API key. Raw key returned only on creation. |
| GET | `/auth/api-keys` | Yes | manage_keys | List current user's API keys. |
| DELETE | `/auth/api-keys/{key_id}` | Yes | manage_keys | Revoke an API key. |
| POST | `/auth/logout` | Yes | read | Revoke all tokens for the current user. |

**Login request:**

```json
POST /api/v1/auth/login
{
  "email": "admin@acme.com",
  "password": "WarlockAdmin2026!"
}
```

**Login response (success):**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "wlk_rt_...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user_id": "uuid",
  "role": "admin"
}
```

**Login response (MFA required):**

```json
{
  "mfa_required": true,
  "mfa_token": "signed_challenge_token",
  "message": "MFA verification required. POST to /auth/mfa/verify with mfa_token and code."
}
```

---

## Compliance (16 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/frameworks` | Yes | read | List all frameworks with control counts. |
| GET | `/frameworks/{framework_id}/controls` | Yes | read | List controls for a framework. |
| GET | `/findings` | Yes | read | Paginated findings list. Filters: severity, source, provider, resource_type, search, observed_after, observed_before. |
| GET | `/findings/{finding_id}` | Yes | read | Single finding detail. |
| GET | `/results` | Yes | read | Paginated control results. Filters: framework, status, control_id, severity, assessor, system_id. |
| GET | `/results/coverage` | Yes | read | Compliance coverage summary per framework. Includes posture_score. |
| GET | `/results/posture` | Yes | read | Posture scores per control with evidence freshness. |
| GET | `/controls/{control_id}` | Yes | read | Full control detail: status counts, passing/failing resources, remediation guidance, assertions. |
| GET | `/cadence` | Yes | read | Monitoring cadence check. Shows stale controls. |
| GET | `/posture/history` | Yes | read | Posture trend data over time. |
| GET | `/sufficiency` | Yes | read | Evidence sufficiency scores per control. |
| GET | `/connectors` | Yes | read | List connector runs with status and event counts. |
| GET | `/connectors/{provider}/status` | Yes | read | Single connector status. |
| GET | `/drift` | Yes | read | Compliance drift events with correlated changes. |
| GET | `/effectiveness` | Yes | read | Control effectiveness: uptime %, MTTR, drift count. |
| GET | `/dashboard/summary` | Yes | read | Executive dashboard: coverage rates, issue counts, risk scores. |

**Coverage response example:**

```json
{
  "items": [
    {
      "framework": "nist_800_53",
      "total": 1176,
      "compliant": 940,
      "non_compliant": 180,
      "partial": 56,
      "not_assessed": 0,
      "rate": 79.9,
      "posture_score": 82.1
    }
  ]
}
```

---

## Governance (43 endpoints)

### Issues (12 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/issues/summary` | Yes | read | Issue counts by status and priority. |
| GET | `/issues` | Yes | read | Paginated issue list. Filters: framework, status, priority, assigned_to, control_id, search, system_id. |
| POST | `/issues` | Yes | write | Create a new issue manually. |
| GET | `/issues/{issue_id}` | Yes | read | Full issue detail with linked control result, remediation, comments, POA&M, compensating controls. |
| PATCH | `/issues/{issue_id}` | Yes | write | Update issue fields (title, priority, due_date, tags, remediation_plan). |
| POST | `/issues/{issue_id}/transition` | Yes | write | Transition issue status (open, assigned, in_progress, resolved, closed, verified, risk_accepted). |
| POST | `/issues/{issue_id}/assign` | Yes | write | Assign issue to user by email. |
| POST | `/issues/{issue_id}/accept-risk` | Yes | write | Accept risk for an issue. |
| POST | `/issues/{issue_id}/evidence` | Yes | write | Attach evidence to an issue. |
| POST | `/issues/{issue_id}/comments` | Yes | write | Add a comment to an issue. |
| POST | `/issues/auto-create` | Yes | write | Auto-create issues from non-compliant control results. |

### Attestations (6 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/attestations` | Yes | read | List attestations. Filters: framework, status. |
| POST | `/attestations` | Yes | write | Create a new attestation. |
| GET | `/attestations/{id}` | Yes | read | Get attestation detail. |
| POST | `/attestations/{id}/submit` | Yes | write | Submit attestation for review. |
| POST | `/attestations/{id}/review` | Yes | write | Submit review of attestation. |
| POST | `/attestations/{id}/approve` | Yes | write | Approve attestation. |
| POST | `/attestations/{id}/reject` | Yes | write | Reject attestation. |

### Audit Engagements (10 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/engagements` | Yes | read | List audit engagements. |
| POST | `/engagements` | Yes | write | Create a new engagement. |
| GET | `/engagements/{id}` | Yes | read | Get engagement detail. |
| PUT | `/engagements/{id}` | Yes | write | Update engagement. |
| DELETE | `/engagements/{id}` | Yes | write | Delete engagement. |
| GET | `/engagements/{id}/evidence` | Yes | read | Get evidence package for engagement. |
| GET | `/engagements/{id}/package` | Yes | read | Download full evidence package. |
| POST | `/engagements/{id}/generate-assertion` | Yes | write | Generate attestation from engagement. |
| GET | `/engagements/{id}/comments` | Yes | read | List audit comments. |
| POST | `/engagements/{id}/comments` | Yes | write | Add audit comment. |

### POA&Ms, Compensating Controls, Risk Acceptances (5 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| POST | `/comments/{comment_id}/resolve` | Yes | write | Resolve an audit comment. |
| GET | `/poams` | Yes | read | List Plans of Action & Milestones. Filters: framework, status, overdue. |
| POST | `/poams/{poam_id}/extend` | Yes | write | Extend POA&M deadline. |
| GET | `/compensating-controls` | Yes | read | List compensating controls. |
| GET | `/risk-acceptances` | Yes | read | List risk acceptances. |

---

## Risk (7 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| POST | `/risk/analyze` | Yes | read | Run FAIR Monte Carlo risk quantification. Set `ai: true` for AI narrative. |
| GET | `/risk/cache-stats` | Yes | read | Monte Carlo cache statistics. |
| GET | `/vendors/risk` | Yes | read | Vendor risk scores from SecurityScorecard data. |
| GET | `/policies/coverage` | Yes | read | Policy documentation coverage for a framework. |
| GET | `/policies/gaps` | Yes | read | Controls with no policy documentation. |
| POST | `/audit-simulation` | Yes | read | Simulate what an auditor would see at a future date. |
| POST | `/frameworks/diff` | Yes | read | Compare two framework versions. |
| POST | `/impact-check` | Yes | read | Check compliance impact of changed assertion/policy files. |

**Risk analysis request:**

```json
POST /api/v1/risk/analyze
{
  "framework": "nist_800_53",
  "iterations": 10000,
  "ai": true
}
```

---

## Admin (44 endpoints)

### User Management (4 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/users` | Yes | manage_users | List all users. |
| GET | `/users/{user_id}` | Yes | manage_users | Get user detail. |
| PUT | `/users/{user_id}` | Yes | manage_users | Update user (role, active, allowed_frameworks, allowed_sources). |
| DELETE | `/users/{user_id}` | Yes | manage_users | Deactivate a user. |

### System Profiles (7 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/systems` | Yes | read | List active system profiles. |
| POST | `/systems` | Yes | write | Create a system profile. |
| GET | `/systems/expiring` | Yes | read | Systems with expiring ATOs. |
| GET | `/systems/{id}` | Yes | read | System profile detail. |
| PATCH | `/systems/{id}` | Yes | write | Update system profile. |
| DELETE | `/systems/{id}` | Yes | write | Deactivate system profile. |
| GET | `/systems/{id}/findings` | Yes | read | Findings scoped to a system. |
| GET | `/systems/{id}/posture` | Yes | read | System-level posture summary. |
| GET | `/systems/{id}/ssp-header` | Yes | read | SSP header data for a system. |

### Personnel (5 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/personnel` | Yes | read | Paginated personnel list. Filters: department, status. |
| GET | `/personnel/flags` | Yes | read | Flagged personnel (risk score > 0). |
| GET | `/personnel/terminated-active` | Yes | read | Terminated employees still active in IdP. |
| GET | `/personnel/summary` | Yes | read | Personnel summary: counts by status, MFA adoption, training. |
| POST | `/personnel/sync` | Yes | write | Sync personnel from HR, IdP, and training findings. |
| GET | `/personnel/{id}` | Yes | read | Single personnel record. |

### Data Retention (4 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/retention/report` | Yes | read | Retention report: record ages, purgeable counts, legal holds. |
| POST | `/retention/purge` | Yes | write | Purge expired records (dry-run by default). |
| POST | `/retention/legal-hold` | Yes | write | Create a legal hold. |
| GET | `/retention/legal-holds` | Yes | read | List active legal holds. |
| DELETE | `/retention/legal-holds/{id}` | Yes | write | Release a legal hold. |

### Tools (5 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/tools` | Yes | read | List configured tool integrations and their status. |
| POST | `/tools/{provider}/test` | Yes | write | Test connectivity to a tool. |
| POST | `/tools/test-all` | Yes | write | Test connectivity to all configured tools. |
| GET | `/tools/{provider}/env-vars` | Yes | read | List required environment variables for a tool. |
| GET | `/tools/{provider}/history` | Yes | read | Tool connector run history. |

### Audit Trail (2 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/audit-trail` | Yes | read | Paginated audit trail. Filters: entity_type, entity_id, actor, date range. |
| GET | `/audit-trail/verify` | Yes | read | Verify SHA-256 hash chain integrity. |

### Alert Configuration (2 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/alerts/config` | Yes | read | Current alert configuration (Slack, PagerDuty, Jira, ServiceNow). |
| PUT | `/alerts/config` | Yes | write | Update alert configuration. |

### Data Silos (7 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/data-silos` | Yes | read | Paginated data silo list. Filters: type, classification, provider. |
| POST | `/data-silos` | Yes | write | Register a data silo. |
| GET | `/data-silos/unclassified` | Yes | read | Silos without classification. |
| GET | `/data-silos/unprotected` | Yes | read | Silos missing encryption or logging. |
| GET | `/data-silos/summary` | Yes | read | Data silo summary: counts by type, classification, protection. |
| POST | `/data-silos/discover` | Yes | write | Auto-discover data silos from findings. |
| GET | `/data-silos/{id}` | Yes | read | Single data silo detail. |
| PATCH | `/data-silos/{id}` | Yes | write | Update data silo classification/metadata. |

### GDPR (2 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/gdpr/export` | Yes | read | GDPR data export for a subject. |
| DELETE | `/gdpr/erase` | Yes | write | GDPR erasure request. |

---

## Pipeline (5 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| POST | `/pipeline/collect` | Yes | run_pipeline | Trigger a full pipeline run in the background. Returns 409 if already running. |
| GET | `/pipeline/status` | Yes | read | Current pipeline status and last run stats. |
| GET | `/scheduler/status` | Yes | read | Scheduler status: running, interval, run count, last/next run. |
| POST | `/scheduler/start` | Yes | run_pipeline | Start the pipeline scheduler. |
| POST | `/scheduler/stop` | Yes | run_pipeline | Stop the pipeline scheduler. |

**Pipeline collect response:**

```json
{
  "status": "started",
  "run_id": "uuid"
}
```

---

## Export (13 endpoints)

### OSCAL (1 endpoint)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| POST | `/export/oscal` | Yes | export | Export OSCAL JSON (assessment results, SSP, or POA&M). |

**OSCAL export request:**

```json
POST /api/v1/export/oscal
{
  "export_type": "ar",
  "framework": "nist_800_53",
  "system_name": "My System"
}
```

### Questionnaire Templates (3 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/questionnaires/templates` | Yes | read | List active questionnaire templates. |
| POST | `/questionnaires/templates` | Yes | write | Create a questionnaire template. |
| POST | `/questionnaires/templates/seed` | Yes | write | Seed default templates (SIG Lite, DDQ). |

### Questionnaires (8 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/questionnaires/overdue` | Yes | read | List overdue questionnaires. |
| GET | `/questionnaires` | Yes | read | Paginated questionnaire list. Filters: vendor_name, status. |
| POST | `/questionnaires` | Yes | write | Create and send a questionnaire. |
| GET | `/questionnaires/{id}` | Yes | read | Get questionnaire detail. |
| POST | `/questionnaires/{id}/responses` | Yes | write | Submit questionnaire responses. |
| POST | `/questionnaires/{id}/score` | Yes | write | Score a completed questionnaire. |
| POST | `/questionnaires/{id}/ai-suggest` | Yes | write | AI-suggested answers for a questionnaire. |
| POST | `/questionnaires/{id}/transition` | Yes | write | Transition questionnaire status (draft, sent, in_progress, completed, reviewed, accepted, rejected). |

---

## AI (8 endpoints)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/ai/status` | Yes | read | AI service availability and configuration. |
| GET | `/ai/models` | Yes | read | List available models for the configured provider. |
| POST | `/ai/configure` | Yes | write | Validate provider connectivity. Does not persist settings. |
| POST | `/ai/models` | Yes | write | Validate a specific model is reachable. |
| POST | `/ai/reason` | Yes | read | General-purpose AI reasoning. Task must be a valid AITask enum value. |
| POST | `/ai/converse` | Yes | read | Multi-turn AI conversation tied to a compliance entity. |
| GET | `/ai/conversations/{session_id}` | Yes | read | Full message history for a conversation. |
| DELETE | `/ai/conversations/{session_id}` | Yes | write | Delete a conversation session. |
| GET | `/ai/audit` | Yes | read | Paginated AI conversation audit log. |

**AI reason request:**

```json
POST /api/v1/ai/reason
{
  "task": "executive_report",
  "context": {
    "frameworks": {"nist_800_53": {"compliant": 940, "total": 1176}}
  }
}
```

**AI converse request:**

```json
POST /api/v1/ai/converse
{
  "entity_type": "finding",
  "entity_id": "uuid",
  "message": "What is the best way to remediate this?"
}
```

---

## Trust Portal (9 endpoints) -- Public / Mixed Auth

The trust portal exposes public compliance posture information. NDA-gated documents require authentication.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/trust/status` | No | Public compliance status summary: frameworks, overall rating, last assessment. |
| GET | `/trust/certifications` | No | Active certifications and attestations. |
| GET | `/trust/security-updates` | No | Recent security improvements and compliance milestones. |
| GET | `/trust/request-access` | No | Form fields for requesting access to detailed compliance docs. |
| POST | `/trust/request-access` | No | Submit NDA access request. Requires `nda_accepted: true`. |
| POST | `/trust/documents` | Yes (admin) | Upload a compliance document (PDF, PNG, JPEG, CSV, JSON; max 50 MB). |
| GET | `/trust/documents` | No | List public-tier documents. NDA/contract tiers return 401. |
| GET | `/trust/documents/{id}/download` | Mixed | Generate time-limited (1h) signed download URL. NDA/contract tier requires auth. |
| GET | `/trust/documents/{id}/file` | Mixed | Serve the raw document file using HMAC-signed token. |
| GET | `/trust/access-requests/{id}/documents` | No | Post-NDA document list (public + nda tier if approved). |

---

## Prometheus Metrics

| Path | Auth | Description |
|------|------|-------------|
| `/metrics` | No | Prometheus metrics endpoint. Available when `prometheus_client` is installed. |

---

## Endpoint Count Summary

| Domain | Routes |
|--------|--------|
| Health | 3 |
| Auth | 9 |
| Compliance | 16 |
| Governance | 43 |
| Risk | 8 |
| Admin | 44 |
| Pipeline | 5 |
| Export | 13 |
| AI | 9 |
| Trust Portal | 10 |
| **Total** | **160** |
