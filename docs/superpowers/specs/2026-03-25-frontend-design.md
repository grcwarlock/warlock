# Warlock Frontend — Design Spec

**Date:** 2026-03-25
**Status:** Draft

## Product Identity

Warlock is **GRC as code** — a pipeline-first compliance platform built for engineers. Compliance is treated as telemetry, not spreadsheets. Evidence flows through an immutable 4-stage pipeline with SHA-256 integrity hashing. Every control result traces back to its raw API response.

The frontend must reflect this identity at every layer:
- **Executive view (dashboard)**: Polished SaaS — posture scores, KRIs, framework coverage, trends. Where the CISO looks.
- **Engineering view (everything below)**: Infrastructure-aware drill-downs — real resource ARNs, terraform remediation, assertion logic, hash chain verification, drift events with code-level correlation. Where the security engineer works.

The transition between these layers is seamless. Click a red KRI → see the failing control → see the specific S3 bucket → see the terraform fix. That drill-down IS the product.

## Tech Stack

- **Framework:** Vite + React 18 + TypeScript
- **Components:** shadcn/ui (Radix primitives + Tailwind CSS)
- **Charts:** Recharts (lightweight, React-native)
- **Routing:** React Router v6
- **State:** TanStack Query (server state) + React context (UI state)
- **Theme:** Dark mode (zinc palette), Geist Sans for UI, Geist Mono for code/data
- **API:** Existing FastAPI backend (152 endpoints), JWT auth
- **Location:** `frontend/` directory in the repo
- **Dev:** Vite dev server proxied to FastAPI on :8000
- **Production:** Static build served by FastAPI or reverse proxy

## Layout

**Collapsible icon rail sidebar:**
- Default: 56px icon rail (icons + tooltips)
- Hover/click: slides to ~240px with labels
- Persists collapse state in localStorage
- Sections grouped with dividers

**Sidebar sections:**

| Icon | Label | Route |
|---|---|---|
| ◉ | Dashboard | `/` |
| ⊞ | Pipeline | `/pipeline` |
| ☰ | Compliance | `/compliance` |
| ⚑ | Findings | `/findings` |
| ✓ | Remediation | `/remediation` |
| ▲ | Incidents | `/incidents` |
| ◆ | Risk | `/risk` |
| ⊡ | Audit | `/audit` |
| ⚙ | Settings | `/settings` |

**Top bar:** Breadcrumb trail (Pipeline / AWS / S3 / acme-prod-data), search (Cmd+K), user menu, notification bell.

## Pages & Drill-Down Paths

### 1. Dashboard (`/`)

**Purpose:** Executive posture overview. First thing anyone sees.

**API endpoints:**
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/results/coverage`
- `GET /api/v1/posture/history`
- `GET /api/v1/cadence`
- `GET /api/v1/drift`

**Layout:**
- **Top row:** 4 KPI cards — total findings (with severity breakdown), compliance rate (%), active POA&Ms, pipeline health (last run status + duration)
- **Middle row:** Posture trend chart (90 days, one line per framework) + Framework coverage heatmap grid (14 frameworks × status)
- **Bottom row:** Recent drift events table (last 10) + KRI indicators (5 KRIs with red/amber/green)

**Interactions:**
- Click KPI card → navigates to detail page (findings, compliance, remediation, pipeline)
- Click framework in heatmap → `/compliance/{framework_id}`
- Click drift event → `/findings/{finding_id}`
- Click KRI → filtered view of the underlying data

### 2. Pipeline (`/pipeline`)

**Purpose:** Infrastructure-aware view of all connectors, their health, and the data they produce. This is the "GRC as code" view.

**API endpoints:**
- `GET /api/v1/connectors`
- `GET /api/v1/connectors/{provider}/status`
- `GET /api/v1/pipeline/status`
- `GET /api/v1/findings?source={provider}`
- `POST /api/v1/pipeline/collect`

**Drill-down chain:**
```
/pipeline                          → All connectors grouped by source type
/pipeline/{provider}               → Provider detail (AWS: S3, EC2, IAM, etc.)
/pipeline/{provider}/{event_type}  → Findings for that event type
/pipeline/{provider}/{event_type}/{finding_id} → Finding detail + controls + remediation
```

**Level 1 — Connector grid:**
- Cards grouped by source type (Cloud, EDR, IAM, Scanner, SIEM, etc.)
- Each card: provider logo/icon, name, status dot (green/red/gray), last run time, finding count
- Click card → Level 2
- "Run Pipeline" button → triggers `POST /api/v1/pipeline/collect`

**Level 2 — Provider detail (e.g., AWS):**
- Breadcrumb: Pipeline / AWS
- Service breakdown: S3, EC2, IAM, VPC, CloudTrail, GuardDuty — each with finding counts + severity badges
- Resource table: all resources discovered by this provider, with ARN/ID, resource type, finding count
- Click service or resource → Level 3

**Level 3 — Event type findings (e.g., AWS / S3):**
- Breadcrumb: Pipeline / AWS / S3
- Resource cards: each S3 bucket with compliance status, tags, finding severity breakdown
- Border color: red (critical findings), amber (high/medium), green (compliant)
- Click resource card → Level 4

**Level 4 — Finding detail:**
- Breadcrumb: Pipeline / AWS / S3 / acme-prod-data
- Finding header: title, severity badge, observed_at, source
- Raw event viewer: collapsible JSON of the verbatim API response, sha256 hash displayed
- Mapped controls: table of all controls this finding maps to, with status, framework, confidence
- Click control → `/compliance/{framework}/{control_id}`
- **Remediation panel** (right side or tabbed):
  - **Playbook tab:** Deterministic remediation steps with terraform/CLI code blocks, copy button
  - **AI tab:** (if AI configured) Context-aware remediation from `/api/v1/ai/reason`, markdown rendered
  - **POA&M tab:** Create POA&M from this finding, or link to existing

### 3. Compliance (`/compliance`)

**Purpose:** Framework-centric view. Browse controls, see evidence, understand assessment logic.

**API endpoints:**
- `GET /api/v1/results/coverage`
- `GET /api/v1/results?framework={id}`
- `GET /api/v1/frameworks`
- `GET /api/v1/frameworks/{id}/controls`
- `GET /api/v1/controls/{control_id}`
- `GET /api/v1/effectiveness`
- `GET /api/v1/sufficiency`

**Drill-down chain:**
```
/compliance                        → Framework overview grid
/compliance/{framework_id}         → Control families + status breakdown
/compliance/{framework_id}/{control_id} → Control detail + evidence + assessment
```

**Level 1 — Framework grid:**
- 14 framework cards (NIST, SOC 2, ISO, etc.)
- Each card: total controls, compliant %, non-compliant count, last assessed
- Progress ring or bar showing compliance rate
- Click → Level 2

**Level 2 — Framework detail (e.g., NIST 800-53):**
- Breadcrumb: Compliance / NIST 800-53
- Control families as rows: AC, AU, CM, IA, SC, etc.
- Each family: control count, pass/fail/not-assessed breakdown, expandable
- Expand family → individual controls with status badges
- Click control → Level 3

**Level 3 — Control detail (e.g., AC-2):**
- Breadcrumb: Compliance / NIST 800-53 / AC-2
- **Status:** compliant/non_compliant/partial/not_assessed with explanation
- **Assessment method:** which tier assessed it (assertion, AI, OPA, inheritance)
- **Assertion logic:** if Tier 1, show the assertion name(s) and pass/fail reasons
- **Evidence:** linked findings with source, severity, observed_at
- **Crosswalks:** other frameworks where this control maps (SOC 2 CC6.1, ISO A.8.5, etc.) — clickable
- **History:** status changes over time (from PostureSnapshot data)
- **Remediation:** same playbook + AI panel as finding detail

### 4. Findings (`/findings`)

**Purpose:** All findings across all sources, filterable and sortable.

**API endpoints:**
- `GET /api/v1/findings`
- `GET /api/v1/findings/{finding_id}`

**Layout:**
- **Filters bar:** source type, provider, severity, status (open/suppressed/false-positive), age range, framework
- **Table:** sortable columns — title, source, severity, resource_id, observed_at, control count, status
- **Sidebar detail:** click row → slide-out panel with full finding detail (same as Pipeline Level 4)
- **Bulk actions:** suppress, assign, create POA&M, export

### 5. Remediation (`/remediation`)

**Purpose:** POA&M lifecycle, compensating controls, risk acceptances. The "action" view.

**API endpoints:**
- `GET /api/v1/poams`
- `POST /api/v1/poams/{id}/extend`
- `GET /api/v1/compensating-controls`
- `GET /api/v1/risk-acceptances`
- `GET /api/v1/remediations`
- `PATCH /api/v1/remediations/{id}/assign`
- `PATCH /api/v1/remediations/{id}/start`
- `PATCH /api/v1/remediations/{id}/submit-verification`
- `PATCH /api/v1/remediations/{id}/verify`

**Layout — tabbed:**

**POA&Ms tab:**
- View toggle: table or kanban board (columns = status: draft, open, in_progress, remediated, verified, completed)
- Each card: weakness description, framework/control, severity, scheduled_completion, overdue badge
- Click → POA&M detail: milestones timeline, linked finding, cost estimate, owner, state machine controls (transition buttons)
- "Create POA&M" button

**Compensating Controls tab:**
- Table: control description, linked POA&M, status (proposed/approved/active/expired), expiry date
- Click → detail with approval history

**Risk Acceptances tab:**
- Table: risk description, AO who approved, expiry date, linked control
- Click → detail with approval chain

**Remediations tab:**
- Table: title, status, completion %, assigned to
- Click → step-by-step remediation plan with completion tracking

### 6. Incidents (`/incidents`)

**Purpose:** Security incidents with classification, severity, timeline.

**API endpoints:**
- `GET /api/v1/issues?source=incident`
- `GET /api/v1/issues/{id}`
- `POST /api/v1/issues/{id}/transition`
- `POST /api/v1/issues/{id}/comments`

**Layout:**
- **Table:** severity badge, title, status, classification, assigned_to, created_at
- **Filters:** severity, status, classification
- Click → incident detail:
  - Timeline (comments + state transitions as a vertical timeline)
  - Linked findings (which finding triggered this incident)
  - Affected controls (blast radius)
  - Response actions (comments, transitions)

### 7. Risk (`/risk`)

**Purpose:** Risk quantification, vendor risk, risk register.

**API endpoints:**
- `GET /api/v1/vendors/risk`
- `GET /api/v1/risk-acceptances`
- `POST /api/v1/risk/analyze`

**Layout — tabbed:**

**Vendor Risk tab:**
- Table: vendor name, risk score, tier, last assessment, SOC 2 status
- Click → vendor detail: score breakdown, sub-processors, assessment history

**Risk Register tab:**
- Risk acceptances + risk analyses
- Click → FAIR Monte Carlo results (if cached)

### 8. Audit (`/audit`)

**Purpose:** Audit engagement management, evidence packaging, hash chain verification.

**API endpoints:**
- `GET /api/v1/engagements`
- `GET /api/v1/engagements/{id}`
- `GET /api/v1/engagements/{id}/evidence`
- `GET /api/v1/engagements/{id}/package`
- `GET /api/v1/audit-trail`
- `GET /api/v1/audit-trail/verify`
- `POST /api/v1/export/oscal`
- `GET /api/v1/attestations`

**Layout — tabbed:**

**Engagements tab:**
- Table: auditor firm, framework, status, start/end dates
- Click → engagement detail: evidence requests, comments, evidence package download

**Audit Trail tab:**
- Scrollable log of hash-chained audit entries
- "Verify Chain" button → calls `/audit-trail/verify`, shows result with green checkmark or broken link indicator
- Each entry: sequence, action, entity_type, timestamp, sha256 hash (monospace, truncated)

**Attestations tab:**
- Table: framework, status (draft/submitted/approved/rejected), expiry
- Click → detail with approval workflow buttons

**Export tab:**
- OSCAL export button (Assessment Results, SSP, POA&M)
- Evidence binder download per engagement

### 9. Settings (`/settings`)

**Purpose:** Platform configuration. This is where AI gets configured.

**API endpoints:**
- `GET /api/v1/users`
- `POST /api/v1/auth/register`
- `GET /api/v1/auth/api-keys`
- `POST /api/v1/auth/api-keys`
- `GET /api/v1/ai/status`
- `POST /api/v1/ai/configure`
- `GET /api/v1/alerts/config`
- `PUT /api/v1/alerts/config`
- `GET /api/v1/connectors`
- `GET /api/v1/tools`
- `POST /api/v1/tools/{provider}/test`

**Layout — tabbed:**

**AI Configuration tab:**
- Current status: provider, model, enabled/disabled
- Form: provider dropdown (Anthropic/OpenAI/Gemini/Ollama), API key input (password field), model selector, base URL (for Ollama)
- "Test Connection" button → validates key
- "Save" → calls `POST /api/v1/ai/configure`
- **This is real. Entering a key enables AI across the platform immediately.**

**Users tab:**
- Table: email, role, MFA status, last login
- Create user form

**API Keys tab:**
- Table: key name, scopes, created_at, last_used
- Create key button

**Connectors tab:**
- Table: all 165 connectors, enabled/disabled status, last health check
- Click → connector detail: required env vars, test button

**Alerts tab:**
- Slack webhook URL, PagerDuty routing key, Jira config
- Per-channel severity thresholds

## Authentication Flow

1. Login page at `/login` — email + password form
2. `POST /api/v1/auth/login` → JWT token
3. Token stored in httpOnly cookie or localStorage (with refresh via `/api/v1/auth/refresh`)
4. All API calls include `Authorization: Bearer {token}`
5. If MFA enabled: `POST /api/v1/auth/mfa/verify` with TOTP code before granting access
6. 401 response → redirect to `/login`
7. Demo credentials pre-filled: `admin@acme.com` / `WarlockAdmin2026!`

## Visual Design System

**Palette (zinc-based dark):**
- Background: `#09090b` (zinc-950)
- Surface: `#18181b` (zinc-900)
- Border: `#27272a` (zinc-800)
- Muted text: `#71717a` (zinc-500)
- Primary text: `#fafafa` (zinc-50)
- Accent: `#6366f1` (indigo-500) — primary actions, active states
- Success: `#22c55e` — compliant, healthy, passing
- Warning: `#f59e0b` — partial, amber KRI, approaching deadline
- Danger: `#ef4444` — non_compliant, critical, failed, overdue
- AI accent: `#a78bfa` (violet-400) — AI-powered features

**Typography:**
- UI labels, navigation: Geist Sans
- Code, ARNs, hashes, IDs, terraform: Geist Mono
- Data values (numbers, scores): Geist Sans semibold

**Component patterns:**
- Status badges: colored background with matching text (e.g., `bg-red-500/10 text-red-400`)
- Cards: `bg-zinc-900 border border-zinc-800 rounded-lg`
- Cards with status: border color matches status (red/amber/green)
- Code blocks: `bg-zinc-950 border border-zinc-800 font-mono text-sm`
- Tables: zebra-striped rows, sticky header, sortable columns
- Breadcrumbs: slash-separated, monospace path-like (`Pipeline / AWS / S3`)

## File Structure

```
frontend/
  index.html
  vite.config.ts
  tsconfig.json
  tailwind.config.ts
  package.json
  src/
    main.tsx                    — App entry, router, providers
    api/
      client.ts                — Axios/fetch wrapper with JWT
      endpoints.ts             — Typed API functions
    components/
      layout/
        AppShell.tsx            — Sidebar + topbar + content area
        Sidebar.tsx             — Collapsible icon rail
        Topbar.tsx              — Breadcrumbs, search, user menu
      ui/                      — shadcn/ui components (auto-installed)
      shared/
        StatusBadge.tsx         — Compliant/non-compliant/partial/etc.
        SeverityBadge.tsx       — Critical/high/medium/low/info
        CodeBlock.tsx           — Syntax-highlighted code display
        RemediationPanel.tsx    — Playbook + AI tabs
        KPICard.tsx             — Dashboard metric cards
        DataTable.tsx           — Sortable/filterable table wrapper
    pages/
      Dashboard.tsx
      pipeline/
        PipelineOverview.tsx    — Connector grid
        ProviderDetail.tsx      — AWS → services
        EventTypeFindings.tsx   — S3 → resources
        FindingDetail.tsx       — Resource → finding → controls → remediation
      compliance/
        ComplianceOverview.tsx  — Framework grid
        FrameworkDetail.tsx     — Control families
        ControlDetail.tsx       — Individual control + evidence + assessment
      findings/
        FindingsTable.tsx       — Filterable findings list
      remediation/
        RemediationOverview.tsx — Tabbed: POA&Ms, compensating, risk-accept, remediations
        POAMDetail.tsx          — POA&M lifecycle detail
      incidents/
        IncidentsList.tsx       — Incident table
        IncidentDetail.tsx      — Timeline + blast radius
      risk/
        RiskOverview.tsx        — Tabbed: vendor risk, risk register
        VendorDetail.tsx        — Vendor score breakdown
      audit/
        AuditOverview.tsx       — Tabbed: engagements, trail, attestations, export
        EngagementDetail.tsx    — Evidence requests + package
      settings/
        SettingsOverview.tsx    — Tabbed: AI, users, API keys, connectors, alerts
    hooks/
      useAuth.ts               — Login/logout/token management
      useApi.ts                — TanStack Query wrappers
    lib/
      remediation-playbooks.ts — Hardcoded remediation templates per control
```

## Implementation Priority

1. **Auth + Shell** — Login, sidebar, topbar, routing
2. **Dashboard** — KPI cards, framework grid, posture chart
3. **Pipeline drill-down** — The marquee feature (connector → service → resource → finding → control → remediation)
4. **Settings (AI config)** — Real AI key entry (needed before pipeline remediation AI tab works)
5. **Compliance** — Framework → control → evidence
6. **Findings** — Table + filters
7. **Remediation** — POA&M board
8. **Incidents** — Table + detail
9. **Risk** — Vendor scores
10. **Audit** — Engagements + hash chain

## API Gaps (Must Fix Before or During Frontend Build)

1. **Finding → Controls drill-down:** `GET /api/v1/results` lacks a `finding_id` filter. Add `finding_id` query parameter to the results endpoint so the pipeline drill-down can show which controls a finding maps to. Without this, the core drill-down chain is broken.

2. **Posture history for dashboard:** `GET /api/v1/posture/history` requires a `framework` query parameter. The dashboard trend chart needs all frameworks. Either make `framework` optional (returns all), or the frontend loops over frameworks from `/results/coverage`.

3. **Crosswalk data not in API:** `GET /api/v1/controls/{id}` returns which frameworks a control appears in, but not the equivalent controls in other frameworks. Add crosswalk mappings to the control detail response, or defer to Phase 2.

4. **Connector enable/disable:** The connectors API always returns `enabled=True`. No toggle mechanism exists. The Settings connectors tab will be read-only (health status, env var display) until a toggle endpoint is added.

## Non-Goals (This Spec)

- Privacy module (deferred to later this year)
- Trust Portal (public-facing status page — exists in backend but not in scope for internal UI)
- Questionnaire management (vendor DDQ/SIG workflow — exists in API, Phase 2 candidate)
- System Profiles page (CRUD for authorization boundaries — accessible via Settings or Phase 2)
- Real-time WebSocket updates (polling is fine for demo)
- Mobile responsive (desktop-first, 1280px+ viewport)
- User registration (admin creates users in settings)
- Multi-tenant (single tenant for demo)
