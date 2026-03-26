# Frontend Rebuild — Spec

**Date:** 2026-03-25
**Status:** Approved by user

## Problem Statement

The current frontend is unusable for a GRC engineer. It shows generic tables with wrong math, doesn't wire to actual API data, and is missing two critical backend features. A GRC engineer needs to:

1. See infrastructure topology and click into it
2. Click a failing control → see exactly which resources are failing and why
3. Get actionable remediation (steps + executable commands)
4. Drill from source type → provider → service → resource → finding → control → remediation (7 levels)

## What Exists in Backend (Verified 2026-03-25)

### Working
- `GET /api/v1/controls/{control_id}?ai=true` → returns failing_resources (with resource_id, resource_type, source, provider, region, severity, finding_title), passing_resources, remediation playbook, AI-enhanced remediation
- 36 assertion remediation playbooks (summary, steps, console_path, recommended_reading)
- `get_ai_control_remediation()` generates per-resource AI remediation when AI configured
- Full source hierarchy in data: 27 source_types → 165 providers → event_types → resources → 5,483 findings → 373,852 control results
- Finding → ControlMapping → ControlResult chain intact
- Assertions produce specific failure reasons

### Missing (Must Build)
1. **Resource topology graph API** — endpoint that returns resources grouped by provider/region with relationships, suitable for a visual graph/tree. Data exists in findings/raw_events, just needs an aggregation endpoint.
2. **Executable remediation sandbox** — ability to generate and optionally execute remediation commands (terraform, AWS CLI, etc.) for a specific failing resource. At minimum: generate the exact command. Execution can be a "copy to clipboard" + "run in terminal" pattern for the demo.

### Frontend Bugs (Must Fix in Rebuild)
- Compliance rate math: summed percentages instead of averaging (showed 3283%)
- Pipeline page: flat connector list instead of source_type → provider hierarchy
- Control detail: never called `GET /api/v1/controls/{id}` — showed no failing resources
- Remediation playbooks: existed in API but never fetched or rendered
- Finding detail: never showed mapped controls or remediation

## Phase 1: Backend — Resource Graph + Remediation Commands

### 1.1 Resource Topology API
New endpoint: `GET /api/v1/resources/topology`

Returns a hierarchical structure:
```json
{
  "source_types": [
    {
      "name": "cloud",
      "finding_count": 683,
      "providers": [
        {
          "name": "aws",
          "finding_count": 193,
          "services": [
            {
              "event_type": "s3_bucket_policy",
              "resource_type": "s3_bucket",
              "finding_count": 23,
              "resources": [
                {
                  "resource_id": "arn:aws:s3:::acme-prod-data",
                  "finding_count": 5,
                  "worst_severity": "critical",
                  "controls_affected": ["SC-7", "SC-28", "AC-3"]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Built by aggregating Finding + RawEvent data. Grouped by source_type → source → event_type → resource_id.

### 1.2 Remediation Command Generator
New endpoint: `POST /api/v1/remediation/generate`

Request:
```json
{
  "control_id": "SC-7",
  "resource_id": "arn:aws:s3:::acme-prod-data",
  "resource_type": "s3_bucket",
  "provider": "aws"
}
```

Response:
```json
{
  "playbook": {
    "summary": "Enable server-side encryption on S3 bucket",
    "steps": ["..."],
    "console_path": "S3 > Bucket > Properties > Default encryption"
  },
  "commands": {
    "terraform": "resource \"aws_s3_bucket_server_side_encryption_configuration\" ...",
    "cli": "aws s3api put-bucket-encryption --bucket acme-prod-data --server-side-encryption-configuration ...",
    "console_url": "https://s3.console.aws.amazon.com/s3/buckets/acme-prod-data?tab=properties"
  },
  "ai_remediation": null
}
```

This uses the existing assertion remediation playbooks + generates provider-specific CLI/terraform commands based on the resource type and provider. For the demo, remediation command templates are hardcoded per (resource_type, assertion_name) pair. AI enhancement is optional.

## Phase 2: Test All API Endpoints

Before rebuilding the frontend, verify every endpoint returns correct data against the demo seed:

```
GET /api/v1/dashboard/summary         → has framework stats, finding counts
GET /api/v1/results/coverage          → has per-framework compliance rates (0-100, not 0-1)
GET /api/v1/controls/AC-2?framework=nist_800_53  → has failing_resources, remediation
GET /api/v1/controls/SC-7?framework=nist_800_53&ai=true  → has AI remediation
GET /api/v1/findings?source=aws       → has findings for AWS
GET /api/v1/findings/{id}             → has full detail with raw_data
GET /api/v1/connectors                → has all 351 with source_type
GET /api/v1/frameworks                → has all 13+ frameworks
GET /api/v1/frameworks/nist_800_53/controls  → has control list
GET /api/v1/drift                     → has drift events
GET /api/v1/poams                     → has POA&Ms
GET /api/v1/resources/topology        → NEW: has resource graph
POST /api/v1/remediation/generate     → NEW: has commands
```

Write a test script that hits every endpoint and validates the response shape.

## Phase 3: Frontend Rebuild

### Design Principles (from user feedback)
1. **Infrastructure-first, not table-first** — show the infrastructure, not spreadsheets
2. **Every click goes deeper** — 7 levels of drill-down, no dead ends
3. **Remediation is the point** — every failing control shows exactly how to fix it with copy-paste commands
4. **Real data only** — if the API doesn't return it, don't show a placeholder. Show what's real.
5. **No login** — auto-authenticate, straight to dashboard

### Page Rebuild Plan

**Dashboard:**
- Fix compliance rate math (average of per-framework rates, capped at 100%)
- KPIs from actual `/dashboard/summary` response
- Framework heatmap from `/results/coverage`
- Resource topology preview (collapsible tree showing source_types → top providers)
- Drift events from `/drift`

**Pipeline → renamed "Infrastructure":**
- Level 1: Source type cards (Cloud: 683 findings, EDR: 559, IAM: 483, etc.) from `/resources/topology`
- Level 2: Click Cloud → providers (AWS: 193, Azure: ?, GCP: ?) with service breakdown
- Level 3: Click AWS → services (S3, EC2, IAM, CloudTrail, GuardDuty) with resource counts
- Level 4: Click S3 → resources with finding counts and worst severity
- Level 5: Click resource → findings list
- Level 6: Click finding → detail with controls
- Level 7: Click control → remediation with executable commands

**Compliance:**
- Level 1: Framework cards with correct compliance % from `/results/coverage`
- Level 2: Click framework → control families with pass/fail counts
- Level 3: Click control → `GET /api/v1/controls/{id}` → shows failing resources, passing resources, remediation steps, AI remediation button

**Settings:**
- AI config (keep — this works and is real)
- The rest can stay as-is

**Other pages (findings, remediation, incidents, risk, audit):**
- Fix data wiring to use actual API responses
- Ensure clicking anything navigable links properly

### What to Delete
- `frontend/src/pages/Login.tsx` (already removed from routing)
- All current page implementations in `src/pages/` (replace, don't patch)

### What to Keep
- `frontend/src/api/client.ts` (auto-auth works)
- `frontend/src/api/types.ts` (update as needed)
- `frontend/src/api/endpoints.ts` (add new endpoints)
- `frontend/src/hooks/useApi.ts` (add new hooks)
- `frontend/src/components/layout/` (sidebar, topbar, shell — these work)
- `frontend/src/components/shared/` (badges, code block, KPI card — these work)
- `frontend/src/components/ui/` (shadcn components — keep all)
