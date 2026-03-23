# Warlock Domain Architecture Redesign

**Date:** 2026-03-22
**Status:** Approved
**Author:** Claude + jsn

## Problem

Warlock has 9 CLI domain modules (admin, ai, compliance, export, governance, lake, monitoring, pipeline, risk) that operate as independent stovepipes. A GRC professional cannot:

- Get a cross-domain view ("what do I do today?")
- Navigate from a control to its findings, risk scores, evidence, owners, and remediation plan in one command
- Push operational policies (retention, SLAs, escalation rules) from the CLI
- Have actions in one domain automatically trigger reactions in others

The engine is powerful (82 connectors, 14 frameworks, FAIR Monte Carlo, 3-tier assessment, 24-module data lake) but unusable as an integrated GRC workflow tool.

## Approach

**Event Mesh + Unified Policy Architecture** with noun-centric CLI surface.

Three layers, built incrementally:
- **Layer A — Data Model Tags:** Every entity gets tagged with framework, control_id, system_profile_id, owner. Cross-domain queries become possible.
- **Layer B — DomainService + Composed CLI Views:** Each domain implements a `DomainService` protocol. CLI commands query multiple services to build cross-domain views. Noun-centric commands (`warlock control`, `warlock person`, `warlock vendor`) become hubs.
- **Layer C — Event-Driven Cascade:** Domain events trigger reactions in other domains. One CLI action can cascade across 8+ domains automatically.

The CLI is the primary operational interface. The API serves data and integrations. Both share the same domain services.

## 30 Domains in 8 Solutions

### Solution 1: Mission Control (4 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Briefing | `domains/briefing.py` | Cross-domain priority queue. Queries all domains for urgent items, ranks by severity x staleness x SLA proximity. Filterable by role, framework, mode. | `warlock briefing` |
| Notifications | `domains/notifications.py` | Per-user notification preferences + delivery (terminal, Slack, email). Listens to domain events and routes alerts. | `warlock notifications` |
| Calendar | `domains/calendar.py` | Recurring compliance obligations, audit dates, certification renewals, review cadences. Feeds into briefing. | `warlock calendar` |
| Modes | `domains/modes.py` | User-settable operational mode (audit-prep, remediation-sprint, steady-state, incident-response). Changes what briefing surfaces and what cascade rules are active. | `warlock mode` |

### Solution 2: Compliance Posture (4 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Controls | `domains/controls.py` | Central hub entity. Every control links to findings, assessments, evidence, risk, ownership, POAMs, policies. Richest cross-domain view. | `warlock control` |
| Frameworks | `domains/frameworks.py` | Framework definitions, versioning, diffing, crosswalks, baselines. Wraps existing framework code with DomainService. | `warlock framework` |
| Assessment | `domains/assessment.py` | Assertion engine, AI reasoning, OPA evaluation, anomaly detection. Wraps existing assessor code with event emission. | `warlock assess` |
| Maturity | `domains/maturity.py` | Weighted maturity scoring per framework — evidence quality, automation level, cadence adherence, control effectiveness trends. | `warlock maturity` |

### Solution 3: Evidence Lifecycle (3 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Evidence | `domains/evidence.py` | Evidence vault + quality scoring + freshness + sufficiency. Merges existing vault, sufficiency, and cadence. | `warlock evidence` |
| Collection | `domains/collection.py` | Connector orchestration, pipeline scheduling, CCM. Wraps existing pipeline with event emission. | `warlock collect` |
| Requests | `domains/requests.py` | Evidence request workflow for auditors — assignment, SLA tracking, fulfillment, notifications. | `warlock request` |

### Solution 4: Risk Intelligence (4 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Risk Register | `domains/risk_register.py` | First-class risk entities with lifecycle (identify, assess, treat, monitor, close). Links to controls, assets, vendors. | `warlock risk` |
| Risk Analysis | `domains/risk_analysis.py` | FAIR Monte Carlo engine. Wraps existing risk engine as a service called by the register. | `warlock risk analyze` |
| Risk Treatment | `domains/risk_treatment.py` | Treatment plans (avoid, mitigate, transfer, accept) with cost-benefit. Subsumes existing risk acceptances. | `warlock risk treat` |
| Vendor Risk | `domains/vendor_risk.py` | Persistent vendor registry, scoring, questionnaires, contracts, concentration analysis. Merges scattered vendor pieces. | `warlock vendor` |

### Solution 5: Remediation Ops (3 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Issues | `domains/issues.py` | Unified issue tracker. Merges POAMs and Issues into one entity with type field (poam, finding, audit_finding, manual). Single lifecycle. | `warlock issue` |
| Assignments | `domains/assignments.py` | Ownership + auto-assignment rules + workload balancing + escalation chains. Cross-references personnel. | `warlock assign` |
| SLAs | `domains/slas.py` | SLA definitions per severity/framework, breach tracking, escalation triggers. Feeds briefing urgency ranking. | `warlock sla` |

### Solution 6: Audit & Assurance (3 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Audit | `domains/audit.py` | Engagement management, readiness scoring, simulation, gap analysis. Merges existing audit and simulation. | `warlock audit` |
| Export | `domains/export.py` | OSCAL, binders, FedRAMP, SoA, SOC 2 reports, temporal evidence. Wraps existing export with DomainService. | `warlock export` |
| Trust | `domains/trust.py` | Trust portal, NDA-gated documents, access requests. Wraps existing trust. | `warlock trust` |

### Solution 7: People & Assets (4 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Personnel | `domains/personnel.py` | HR + IdP + training cross-reference. Wraps existing with ownership links to controls and systems. | `warlock person` |
| Assets | `domains/assets.py` | NEW first-class asset registry built from connector findings. Criticality scoring, classification, lifecycle, ownership. | `warlock asset` |
| Systems | `domains/systems.py` | System profiles, authorization boundaries, FIPS 199, dependencies. Container for assets and controls. | `warlock system` |
| Access | `domains/access.py` | Access reviews, privilege analysis, separation of duties. Built from IAM connector data. | `warlock access` |

### Solution 8: Policy & Governance (3 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Policy Engine | `domains/policy_engine.py` | Unified policy store. All operational rules are policy objects — push via CLI, consumed by all domains. | `warlock policy` |
| Calendar (policy-aware) | (merged with Mission Control calendar) | Policy-aware compliance calendar. "PCI requires quarterly access reviews" is a policy that Calendar renders. | `warlock calendar` |
| Governance Workflows | `domains/governance.py` | Attestations, compensating controls, legal holds, GDPR rights, data retention enforcement. Reads from policy engine. | `warlock govern` |

### Cross-Cutting (2 domains)

| Domain | Module | Purpose | CLI |
|---|---|---|---|
| Intelligence | `domains/intelligence.py` | AI reasoning, NL queries, RAG, conversation, anomaly detection. Service any domain can call. | `warlock ask`, `--ai` |
| Integration | `domains/integration.py` | Outbound Jira/SNOW/Slack/PagerDuty + webhook management + connector health. | `warlock integration` |

## Core Interfaces

### DomainService Protocol

```python
class DomainService(Protocol):
    domain_name: str

    def get_urgent_items(self, filters: QueryFilters) -> list[UrgentItem]:
        """What from this domain needs attention? Feeds the briefing."""
        ...

    def get_related_to(self, entity_type: str, entity_id: str) -> list[RelatedItem]:
        """What does this domain know about this entity?"""
        ...

    def get_policy_inputs(self) -> list[PolicyInput]:
        """What policies does this domain consume?"""
        ...

    def handle_event(self, event: DomainEvent) -> list[DomainEvent]:
        """React to a domain event. May return new events (cascade)."""
        ...
```

### QueryFilters

```python
@dataclass
class QueryFilters:
    frameworks: list[str] | None = None
    systems: list[str] | None = None
    owner: str | None = None
    mode: str | None = None                  # audit-prep, remediation, steady-state
    severity_min: str | None = None
    since: datetime | None = None
    limit: int = 50
```

### RelatedItem (cross-domain data shape)

```python
@dataclass
class RelatedItem:
    domain: str
    entity_type: str
    entity_id: str
    summary: str
    severity: str | None = None
    status: str | None = None
    url: str | None = None
    metadata: dict | None = None
```

### UrgentItem (briefing data shape)

```python
@dataclass
class UrgentItem:
    domain: str
    entity_type: str
    entity_id: str
    summary: str
    severity: str
    priority_score: float          # computed: severity x staleness x SLA proximity
    sla_deadline: datetime | None
    assigned_to: str | None
    framework: str | None
    action_hint: str               # "warlock issue transition POAM-123 --to in_progress"
```

### DomainEvent

```python
@dataclass
class DomainEvent:
    event_type: str          # "issue.completed", "finding.created", "policy.changed"
    domain: str
    entity_type: str
    entity_id: str
    actor: str
    timestamp: datetime
    payload: dict
    correlation_id: str      # trace cascades back to the trigger
```

### DomainRegistry

```python
class DomainRegistry:
    def register(self, service: DomainService) -> None: ...
    def get(self, domain_name: str) -> DomainService: ...
    def all_services(self) -> list[DomainService]: ...

    def get_related_to(self, entity_type: str, entity_id: str) -> dict[str, list[RelatedItem]]:
        """Query ALL domains for what they know about this entity."""
        ...

    def get_briefing(self, filters: QueryFilters) -> list[UrgentItem]:
        """Gather urgent items from all domains, sort by priority."""
        ...
```

## Domain Event Bus

Extends the existing `warlock.pipeline.bus.EventBus` to carry domain-level events in addition to pipeline events.

### Event Flow

1. A domain action occurs (CLI command, API call, or cascade reaction)
2. The acting domain emits a `DomainEvent` via the bus
3. Subscribing domains' `handle_event()` methods fire
4. Handler may return new `DomainEvent`s (cascade)
5. Bus processes returned events (recursive, up to max depth)

### Cascade Safety

- **Max depth:** 5 levels. Logs warning and stops if exceeded.
- **Deduplication:** Same event_type + entity_id within a correlation is dropped.
- **Dry-run:** `--dry-run` flag on policy changes shows what would cascade.
- **Audit trail:** Every cascade step creates an `AuditEntry` with correlation_id.
- **Async default:** Cascades process via event bus, not inline. CLI returns immediately.

### Key Event Types

| Event | Emitted By | Subscribers |
|---|---|---|
| `finding.created` | Collection | Assets, Assessment, Issues, Risk, Notifications |
| `control.reassessed` | Assessment | Evidence, Maturity, Risk, Audit, Notifications |
| `control.degraded` | Assessment | Issues, Risk, Briefing, Notifications |
| `issue.created` | Issues | Assignments, SLAs, Calendar, Notifications |
| `issue.completed` | Issues | Assessment, Evidence, SLAs, Audit, Notifications |
| `policy.changed` | Policy Engine | Issues, SLAs, Briefing, Calendar, Notifications |
| `sla.breached` | SLAs | Issues (escalate), Notifications |
| `sla.at_risk` | SLAs | Briefing, Notifications |
| `evidence.stale` | Evidence | Briefing, Cadence, Notifications |
| `audit.started` | Audit | Requests, Briefing, Notifications |
| `vendor.score_changed` | Vendor Risk | Risk Register, Notifications |
| `asset.classified` | Assets | Policy Engine (retention), Evidence, Notifications |
| `person.training_expired` | Personnel | Issues, Briefing, Access, Notifications |

## Unified Policy Engine

### Policy Model

```python
@dataclass
class Policy:
    id: str
    policy_type: str          # retention, sla, classification, risk_appetite,
                              # escalation, auto_assign, cadence, auto_create,
                              # confidence, evidence_requirement, pii
    scope: PolicyScope
    rules: dict               # type-specific rules
    priority: int = 0         # higher wins on conflict
    enabled: bool = True
    created_by: str
    created_at: datetime
    effective_at: datetime
    expires_at: datetime | None = None
    description: str = ""

@dataclass
class PolicyScope:
    frameworks: list[str] | None = None
    systems: list[str] | None = None
    severity: list[str] | None = None
    sources: list[str] | None = None
    asset_types: list[str] | None = None
    departments: list[str] | None = None
```

### Policy Resolution

When a domain asks for a policy, multiple may match. Resolution order:
1. Most specific scope wins (framework+severity beats global)
2. Higher priority wins (tie-breaker)
3. Most recently created wins (final tie-breaker)

### CLI Surface

```bash
# Data governance
warlock policy set retention --framework pci_dss --days 2555
warlock policy set classification --asset-type database --contains-pii high
warlock policy set pii --action pseudonymize --notify privacy-team@acme.com

# Operational
warlock policy set sla --severity critical --remediation-days 14 --escalate-after 7
warlock policy set escalation --severity critical --chain "owner,7d > manager,3d > ciso,1d"
warlock policy set auto-assign --framework soc2 --owner eve@acme.com
warlock policy set auto-create --severity critical --type poam --assign-to owner

# Compliance
warlock policy set risk-appetite --framework soc2 --max-ale 500000
warlock policy set cadence --framework fedramp --frequency monthly --controls "AC-*,IA-*"
warlock policy set confidence --floor 0.8 --framework hipaa
warlock policy set evidence-requirement --control-family AC --min-sources 2 --max-age 90d

# Management
warlock policy list [--type TYPE] [--framework FW]
warlock policy show --control AC-2
warlock policy history [--type TYPE] [--since 7d]
warlock policy export > policies.yaml
warlock policy import policies.yaml
warlock policy set ... --dry-run    # show cascade impact without executing
```

### PolicyEngine Service

```python
class PolicyEngine:
    def get(self, policy_type: str, **context) -> ResolvedPolicy:
        """Get effective policy for context. Resolves conflicts by specificity."""
        ...

    def evaluate(self, policy_type: str, **context) -> bool:
        """Quick boolean check."""
        ...

    def set(self, policy: Policy, actor: str) -> list[DomainEvent]:
        """Store policy, emit policy.changed event."""
        ...
```

## Briefing System

### `warlock briefing`

```
$ warlock briefing

  Warlock Daily Briefing — 2026-03-22 (mode: steady-state)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  OVERDUE (3)
    [CRITICAL] POAM-123  AC-6 privilege escalation — overdue 5d, assigned bob@acme
               → warlock issue transition POAM-123 --to in_progress
    [HIGH]     ISS-456   Evidence request for SOC 2 CC6.1 — overdue 2d
               → warlock request fulfill ISS-456
    [HIGH]     POAM-789  MFA enforcement gap — overdue 1d, assigned eve@acme
               → warlock issue transition POAM-789 --to in_progress

  AT RISK (5)
    [CRITICAL] SLA breach in 3d: 2 critical issues without assignee
               → warlock assign auto --severity critical
    [HIGH]     Audit engagement SOC2-2026 starts in 14d, readiness: 62%
               → warlock audit readiness -f soc2
    ...

  DEGRADED SINCE YESTERDAY (2)
    AC-6 (nist_800_53): compliant → non_compliant  [change: IAM role grant]
    CC6.1 (soc2): partial → non_compliant           [change: Okta policy update]

  STALE EVIDENCE (4)
    SC-7 last assessed 94d ago (cadence: 90d)
    ...

  Filters: --framework, --owner, --mode, --since
```

### Modes

| Mode | What Briefing Emphasizes |
|---|---|
| `steady-state` | Balanced: overdue items, drift, stale evidence, SLA risks |
| `audit-prep` | Audit-focused: evidence gaps, readiness %, stale controls, open requests |
| `remediation-sprint` | Remediation-focused: issue burndown, SLA countdown, unassigned items |
| `incident-response` | Incident-focused: affected controls, blast radius, breach notification deadlines |

Set via `warlock mode set audit-prep` or `warlock briefing --mode audit-prep`.

## Noun-Centric CLI Commands

Every GRC noun becomes a hub command that composes cross-domain data:

### `warlock control AC-2 -f nist_800_53`

```
  Control: AC-2 — Account Management
  Framework: nist_800_53
  ──────────────────────────────────────

  Status:        non_compliant (390 failing resources)
  Maturity:      ★★☆☆☆ (2/5)
  Risk:          $3.5M ALE / $7.8M VaR95
  Evidence:      stale (last assessed 12d ago, cadence: 7d)
  Owner:         eve@acme.com (Engineering)

  Open Issues (2):
    POAM-123  Root account access keys — critical, 5d overdue
    ISS-456   Account provisioning gap — high, assigned

  Compensating Controls (1):
    Weekly privileged access review (effectiveness: 78%)

  Related Frameworks:
    soc2/CC6.2, iso_27001/A.5.18, cmmc_l2/AC.L2-3.1.1

  Drift (30d):
    Mar 18: compliant → non_compliant (correlated: IAM role grant)

  Actions:
    warlock issue create --control AC-2 --type poam
    warlock evidence refresh --control AC-2
    warlock risk analyze --control AC-2
```

### `warlock person eve@acme.com`

```
  Person: Eve Nakamura — Security Engineer
  ──────────────────────────────────────

  HR: active | IdP: active | MFA: yes | Training: current | Risk: 12

  Owns:
    Frameworks: soc2, pci_dss
    Systems: prod-web, prod-api
    Controls: 46 (12 non-compliant, 8 not assessed)

  Open Assignments (4):
    POAM-789  MFA enforcement — high, 1d overdue
    ISS-901   Vendor questionnaire — medium, due in 7d
    ...

  Access Reviews Due:
    Quarterly review for prod-db-01 — due in 12d
```

### `warlock vendor cloudflare`

```
  Vendor: Cloudflare — CDN/Security
  ──────────────────────────────────────

  Risk Score: 82/100 (good)
  Tier: critical
  Contract: expires 2027-01-15
  Last Assessment: 45d ago (cadence: 90d)

  Affected Controls: CC6.7, SC-7, A.8.20
  Questionnaire: SIG Lite — completed, score 88%
  Concentration: 3 systems depend on this vendor

  Actions:
    warlock vendor assess cloudflare
    warlock vendor questionnaire cloudflare --template sig
```

### `warlock asset prod-db-01`

```
  Asset: prod-db-01 — PostgreSQL Database
  ──────────────────────────────────────

  Classification: critical (contains PII, PCI data)
  System: prod-api
  Owner: dba-team@acme.com
  Region: us-east-1

  Findings (12): 3 critical, 5 high, 4 medium
  Controls Affected: 23 across 4 frameworks
  Retention Policy: 2555d (PCI DSS)

  Actions:
    warlock asset classify prod-db-01 --level critical
    warlock asset findings prod-db-01
```

## New Database Models

### Policy (new)

```
policies
  id              UUID PK
  policy_type     VARCHAR(50) NOT NULL
  scope           JSONB NOT NULL
  rules           JSONB NOT NULL
  priority        INT DEFAULT 0
  enabled         BOOL DEFAULT TRUE
  created_by      VARCHAR NOT NULL
  created_at      TIMESTAMP NOT NULL
  effective_at    TIMESTAMP NOT NULL
  expires_at      TIMESTAMP NULL
  description     TEXT
```

### PolicyHistory (new, append-only)

```
policy_history
  id              UUID PK
  policy_id       UUID FK(policies)
  action          VARCHAR(20)   -- created, updated, disabled, deleted
  old_rules       JSONB NULL
  new_rules       JSONB NOT NULL
  actor           VARCHAR NOT NULL
  timestamp       TIMESTAMP NOT NULL
```

### Asset (new)

```
assets
  id              UUID PK
  resource_id     VARCHAR NOT NULL UNIQUE
  resource_type   VARCHAR NOT NULL
  resource_name   VARCHAR
  system_id       UUID FK(system_profiles) NULL
  owner           VARCHAR NULL
  classification  VARCHAR(20) NULL   -- critical, high, medium, low
  criticality     INT NULL           -- 1-10
  status          VARCHAR(20) DEFAULT 'active'
  first_seen      TIMESTAMP NOT NULL
  last_seen       TIMESTAMP NOT NULL
  metadata        JSONB
```

### Vendor (new, replaces in-memory dataclass)

```
vendors
  id              UUID PK
  name            VARCHAR NOT NULL UNIQUE
  tier            VARCHAR(20)   -- critical, high, medium, low
  risk_score      FLOAT NULL
  contract_expires TIMESTAMP NULL
  last_assessment  TIMESTAMP NULL
  assessment_cadence_days INT NULL
  metadata        JSONB
```

### RiskRegisterEntry (new)

```
risk_register
  id              UUID PK
  title           VARCHAR NOT NULL
  description     TEXT
  risk_category   VARCHAR(50)   -- data_breach, service_disruption, compliance_violation, etc.
  status          VARCHAR(20)   -- identified, assessed, treating, monitored, closed
  inherent_likelihood  FLOAT
  inherent_impact      FLOAT
  residual_likelihood  FLOAT NULL
  residual_impact      FLOAT NULL
  treatment_plan  VARCHAR(20)   -- avoid, mitigate, transfer, accept
  control_ids     JSONB         -- linked controls
  asset_ids       JSONB         -- linked assets
  vendor_id       UUID FK(vendors) NULL
  owner           VARCHAR
  created_at      TIMESTAMP
  reviewed_at     TIMESTAMP NULL
  next_review     TIMESTAMP NULL
```

### CalendarEntry (new)

```
calendar_entries
  id              UUID PK
  title           VARCHAR NOT NULL
  entry_type      VARCHAR(30)   -- audit, review, renewal, assessment, deadline
  framework       VARCHAR NULL
  recurrence      VARCHAR(20) NULL   -- daily, weekly, monthly, quarterly, annually
  next_due        TIMESTAMP NOT NULL
  assigned_to     VARCHAR NULL
  policy_id       UUID FK(policies) NULL
  metadata        JSONB
```

### Existing Models — Modifications

- **Issue + POAM → unified Issue**: Add `issue_type` field (poam, finding, audit_finding, manual). POAM-specific fields (milestones, vendor_dependency) become JSONB in metadata. Single table, single lifecycle.
- **Finding**: Add `asset_id` FK to assets table. Populated by asset domain on `finding.created`.
- **ControlResult**: Add `owner` field (denormalized from policy/assignment for query speed).
- **Personnel**: Add `owned_frameworks` JSONB, `owned_systems` JSONB.

## File Structure

```
warlock/
  domains/
    __init__.py              # DomainRegistry, DomainService protocol
    base.py                  # Base classes: DomainService, DomainEvent, QueryFilters,
                             # RelatedItem, UrgentItem, PolicyScope, etc.
    bus.py                   # Extended DomainEventBus (wraps existing EventBus)
    registry.py              # DomainRegistry implementation

    # Solution 1: Mission Control
    briefing.py
    notifications.py
    calendar.py
    modes.py

    # Solution 2: Compliance Posture
    controls.py
    frameworks.py
    assessment.py
    maturity.py

    # Solution 3: Evidence Lifecycle
    evidence.py
    collection.py
    requests.py

    # Solution 4: Risk Intelligence
    risk_register.py
    risk_analysis.py
    risk_treatment.py
    vendor_risk.py

    # Solution 5: Remediation Ops
    issues.py
    assignments.py
    slas.py

    # Solution 6: Audit & Assurance
    audit.py
    export.py
    trust.py

    # Solution 7: People & Assets
    personnel.py
    assets.py
    systems.py
    access.py

    # Solution 8: Policy & Governance
    policy_engine.py
    governance.py

    # Cross-cutting
    intelligence.py
    integration.py

  cli/
    # Refactored to noun-centric commands
    # Each file is a CLI noun, calls domain services
    __init__.py
    briefing.py              # warlock briefing
    control.py               # warlock control <id>
    person.py                # warlock person <email>
    vendor.py                # warlock vendor <name>
    asset.py                 # warlock asset <id>
    policy.py                # warlock policy set/list/show/history/export/import
    issue.py                 # warlock issue (unified POAMs + issues)
    risk.py                  # warlock risk
    audit.py                 # warlock audit
    evidence.py              # warlock evidence
    framework.py             # warlock framework
    system.py                # warlock system
    mode.py                  # warlock mode
    calendar.py              # warlock calendar
    ...                      # remaining nouns
```

Existing modules under `warlock/assessors/`, `warlock/connectors/`, `warlock/normalizers/`, `warlock/pipeline/`, `warlock/workflows/`, `warlock/export/`, `warlock/lake/`, `warlock/ai/` are NOT deleted. Domain services wrap and delegate to them. This is additive, not a rewrite.

## Build Phases

### Phase 1: Foundation (Layer A + core Layer B)
- `warlock/domains/base.py` — all data classes and protocols
- `warlock/domains/registry.py` — DomainRegistry
- `warlock/domains/bus.py` — DomainEventBus
- `warlock/domains/policy_engine.py` — Policy model, PolicyEngine, DB migration
- `warlock policy set/list/show` CLI commands
- 3 domain services as proof of concept: Controls, Issues, Evidence
- `warlock control <id>` cross-domain view (compose from 3 services)
- `warlock briefing` (query 3 services for urgent items)
- New DB models: Policy, PolicyHistory, Asset, Vendor
- Alembic migration
- Default policies seeded

### Phase 2: Remaining Domain Services (Layer B complete)
- Implement DomainService for all 30 domains
- All noun-centric CLI commands
- `warlock person`, `warlock vendor`, `warlock asset`, `warlock system`
- `warlock mode`, `warlock calendar`
- Issue + POAM unification migration
- Asset auto-population from findings
- Vendor persistence migration

### Phase 3: Event Cascade (Layer C)
- Domain event subscriptions wired
- Cascade safety (max depth, dedup, correlation_id)
- `--dry-run` for policy changes
- Auto-create issues from critical findings
- Auto-assignment from policies
- SLA breach detection and escalation
- Re-assessment on issue completion
- Notification routing

### Phase 4: Polish & Advanced Features
- Maturity scoring algorithm
- Risk register with full lifecycle
- Access review workflows
- Briefing modes (audit-prep, remediation-sprint, incident-response)
- `warlock policy export/import`
- Calendar with recurrence engine
- Integration health dashboard
- Demo seed updates for all new domains

## Constraints

- **Additive, not rewrite.** Existing modules are wrapped, not replaced. All 556 tests must continue passing.
- **Demo seed is the acceptance test.** After each phase, `demo_seed.py` must run and produce the expected numbers (81 connectors, 5,008 findings, 373,852 mappings).
- **Policy engine is the single source of truth** for all operational rules. Hardcoded values in existing code (retention days, SLA thresholds, cadence frequencies) migrate to default policies over time.
- **CLI commands return immediately.** Cascades are async via the event bus. Users see results on next `warlock briefing`.
- **Each domain service is independently testable.** No domain directly imports another domain's internals — they communicate via the registry and event bus.
