# Connectors & CLI Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 84 new connectors with matching normalizers, then build ~250 new CLI commands across 17 new CLI modules to expose existing DB models and workflows.

**Note on connector count:** The spec says "86 total — 66 from backlog + 20 from gap analysis" but only lists 84 unique provider names. This plan implements all 84 listed connectors.

**Architecture:** Each connector extends `BaseConnector` (validate/collect/health_check) and registers via `registry.register()` at module level. Each normalizer extends `BaseNormalizer` (can_handle/normalize) with a HANDLERS dispatch dict. CLI modules use Click groups/commands registered via import in `warlock/cli/__init__.py`. All new CLI commands query existing SQLAlchemy models — no new models, no new dependencies.

**Tech Stack:** Python 3.12+, Click, Rich, SQLAlchemy, httpx (existing dep)

**Constraints (from prompt — non-negotiable):**
- Do NOT modify existing connector or normalizer files
- Do NOT modify existing CLI commands
- Do NOT add web/API endpoints
- Do NOT modify existing DB models
- Do NOT add new pip dependencies
- Do NOT update demo_seed.py
- Do NOT create new test files
- Do NOT push anything
- Only files that should be modified (besides new files) are `warlock/cli/__init__.py` (for imports) and `warlock/pipeline/loader.py` (for connector/normalizer registration lists)
- **Spec deviation:** The spec's Phase 4 says "should only be warlock/cli/__init__.py for imports" but `loader.py` MUST also be modified — without it, connectors never get imported and `registry.register()` never fires. This is a necessary spec oversight correction.

---

## Critical Registration Pattern

Every new connector/normalizer must be registered in TWO places:

1. **Module-level self-registration:** Last line of each connector file calls `registry.register("provider_name", ConnectorClass)`. Last line of each normalizer file calls `registry.register(NormalizerClass())`.

2. **Loader import list:** Add the module path to `_CONNECTOR_MODULES` and `_NORMALIZER_MODULES` in `warlock/pipeline/loader.py` (lines 39-121 and 123+). Without this, the module never gets imported and the `registry.register()` call never fires.

## Reference Files (read before coding)

| File | Purpose |
|------|---------|
| `warlock/connectors/base.py` | BaseConnector ABC, SourceType enum (27 values), ConnectorConfig, RawEventData, ConnectorResult, ConnectorRegistry |
| `warlock/connectors/okta.py` | Reference connector (~200 LOC): endpoints, pagination, auth headers, event_type mapping |
| `warlock/connectors/aws.py` | Multi-service connector pattern |
| `warlock/normalizers/base.py` | BaseNormalizer ABC, FindingData dataclass, NormalizerRegistry |
| `warlock/normalizers/okta.py` | Reference normalizer (~310 LOC): HANDLERS dispatch, _base() helper, severity logic |
| `warlock/cli/__init__.py` | CLI root group, helpers (_error, _get_actor, _check_ai_available, console), sub-module imports |
| `warlock/cli/governance.py` | Reference CLI module: @cli.command pattern, Rich tables, --ask AI flag |
| `warlock/cli/lake.py` | Reference CLI group pattern: @cli.group() with nested commands |
| `warlock/db/models.py` | 40 SQLAlchemy models (query these, don't modify) |
| `warlock/pipeline/loader.py:39-173` | `_CONNECTOR_MODULES` and `_NORMALIZER_MODULES` lists — **must add entries here** |

## SourceType Enum Values (already defined in base.py)

```
CLOUD, EDR, IAM, SCANNER, SIEM, CSPM, HRIS, ITSM, TRAINING,
PHYSICAL, CODE, DLP, BACKUP, MDM, GRC, EMAIL, OBSERVABILITY,
NETWORK, COLLABORATION, INFRASTRUCTURE, CONTAINER_SECURITY,
THIRD_PARTY_RISK, AI_ML, DATA_GOVERNANCE, EMAIL_SECURITY, CI_CD, CUSTOM
```

---

# PHASE 1: Build 84 New Connectors + Normalizers

Each connector follows the identical pattern. The work is highly parallelizable — connectors are independent files with no cross-dependencies.

## Connector Template

```python
"""<Provider> connector — <description>.

Collects <what> via <API name>.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

ENDPOINTS: list[tuple[str, str, dict]] = [
    ("/api/v1/<resource>", "<provider>_<resource>", {}),
]


class <Provider>Connector(BaseConnector):
    """Collects compliance telemetry from <Provider>."""

    def validate(self) -> list[str]:
        errors = []
        if not self.config.settings.get("base_url"):
            errors.append("<Provider> base_url is required")
        if not self.get_secret("<PROVIDER>_API_KEY"):
            errors.append("<PROVIDER>_API_KEY environment variable is required")
        return errors

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(source=self.config.provider)
        try:
            import httpx
        except ImportError:
            result.errors.append("httpx not installed")
            return result.complete()

        base_url = self.config.settings.get("base_url", "https://api.<provider>.com")
        api_key = self.get_secret("<PROVIDER>_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}"}

        with httpx.Client(base_url=base_url, headers=headers, timeout=self.config.timeout_seconds) as client:
            for path, event_type, params in ENDPOINTS:
                try:
                    resp = client.get(path, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="<provider>",
                            source_type=SourceType.<TYPE>,
                            provider="<provider>",
                            event_type=event_type,
                            raw_data={"response": data},
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as exc:
                    result.errors.append(f"{event_type}: {exc}")

        return result.complete()

    def health_check(self) -> bool:
        try:
            import httpx
            base_url = self.config.settings.get("base_url", "https://api.<provider>.com")
            api_key = self.get_secret("<PROVIDER>_API_KEY")
            resp = httpx.get(f"{base_url}/api/v1/health", headers={"Authorization": f"Bearer {api_key}"}, timeout=10)
            return resp.status_code < 500
        except Exception:
            return False


registry.register("<provider>", <Provider>Connector)
```

## Normalizer Template

```python
"""<Provider> normalizer — transforms raw <Provider> data into Findings."""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class <Provider>Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "<provider>_<resource>": "_normalize_<resource>",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "<provider>" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "<provider>",
            "source_type": SourceType.<TYPE>,
            "provider": "<provider>",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_<resource>(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = items.get("data", items.get("results", [items]))
        for item in (items if isinstance(items, list) else [items]):
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"<Provider> <resource>: {item.get('name', item.get('id', 'unknown'))}",
                detail=item,
                resource_id=str(item.get("id", "")),
                resource_type="<resource>",
                resource_name=item.get("name", ""),
                severity="info",
                confidence=1.0,
            ))
        return findings


registry.register(<Provider>Normalizer())
```

---

### Task 1: Batch 1A — Incident Ops + CMDB connectors (7 connectors)

**Files to create:**
- `warlock/connectors/pagerduty.py` — PagerDuty (ITSM): incidents, services, on-call, escalation policies
- `warlock/connectors/opsgenie.py` — Opsgenie (ITSM): alerts, incidents, on-call, escalation
- `warlock/connectors/axonius.py` — Axonius (CUSTOM): devices, users, adapters
- `warlock/connectors/servicenow_cmdb.py` — ServiceNow CMDB (ITSM): CIs, relationships, classes
- `warlock/connectors/runzero.py` — runZero (CUSTOM): assets, services, wireless
- `warlock/normalizers/pagerduty.py`
- `warlock/normalizers/opsgenie.py`
- `warlock/normalizers/axonius.py`
- `warlock/normalizers/servicenow_cmdb.py`
- `warlock/normalizers/runzero.py`

**Modify:** `warlock/pipeline/loader.py` — add 5 entries to `_CONNECTOR_MODULES`, 5 to `_NORMALIZER_MODULES`

**SourceType mapping:**
| Provider | SourceType |
|----------|-----------|
| pagerduty | ITSM |
| opsgenie | ITSM |
| axonius | CUSTOM |
| servicenow_cmdb | ITSM |
| runzero | CUSTOM |

- [ ] **Step 1:** Read `warlock/connectors/okta.py` and `warlock/normalizers/okta.py` for reference patterns
- [ ] **Step 2:** Create all 5 connectors using the template above, customizing:
  - API base URLs, auth patterns (Bearer token, API key header, basic auth)
  - Relevant endpoints and event_types (e.g., `pagerduty_incidents`, `pagerduty_services`, `pagerduty_oncall`)
  - Provider-specific pagination (offset-based, cursor-based, Link header)
- [ ] **Step 3:** Create all 5 matching normalizers with appropriate HANDLERS dicts
- [ ] **Step 4:** Add all 10 modules to `_CONNECTOR_MODULES` and `_NORMALIZER_MODULES` in `warlock/pipeline/loader.py`
- [ ] **Step 5:** Verify imports:
  ```bash
  python -c "from warlock.connectors.pagerduty import *; from warlock.connectors.opsgenie import *; from warlock.connectors.axonius import *; from warlock.connectors.servicenow_cmdb import *; from warlock.connectors.runzero import *"
  python -c "from warlock.normalizers.pagerduty import *; from warlock.normalizers.opsgenie import *; from warlock.normalizers.axonius import *; from warlock.normalizers.servicenow_cmdb import *; from warlock.normalizers.runzero import *"
  ```
- [ ] **Step 6:** Run `pytest tests/ -x -q` — expect test count to remain at baseline (606 passed, 0 failed — no new test files are created in this plan)
- [ ] **Step 7:** Commit: `feat(connectors): add pagerduty, opsgenie, axonius, servicenow_cmdb, runzero`

### Task 2: Batch 1B — Patch + Cert + Secrets Mgmt connectors (8 connectors)

**Files to create:**
- `warlock/connectors/patch_mgmt_microsoft.py` — Microsoft patching (MDM)
- `warlock/connectors/ivanti.py` — Ivanti Patch (MDM)
- `warlock/connectors/venafi.py` — Venafi cert mgmt (CUSTOM)
- `warlock/connectors/aws_acm.py` — AWS Certificate Manager (CLOUD)
- `warlock/connectors/digicert.py` — DigiCert CertCentral (CUSTOM)
- `warlock/connectors/aws_secrets.py` — AWS Secrets Manager (CLOUD)
- `warlock/connectors/azure_keyvault.py` — Azure Key Vault (CLOUD)
- `warlock/connectors/gcp_secrets.py` — GCP Secret Manager (CLOUD)
- Matching normalizers (8 files)

**Modify:** `warlock/pipeline/loader.py` — add 8+8 entries

**SourceType mapping:**
| Provider | SourceType |
|----------|-----------|
| patch_mgmt_microsoft | MDM |
| ivanti | MDM |
| venafi | CUSTOM |
| aws_acm | CLOUD |
| digicert | CUSTOM |
| aws_secrets | CLOUD |
| azure_keyvault | CLOUD |
| gcp_secrets | CLOUD |

- [ ] **Step 1:** Create all 8 connectors with provider-specific endpoints
  - `patch_mgmt_microsoft`: Microsoft Graph API for Intune patch compliance
  - `aws_acm`: boto3-style ACM endpoints (certificates, expiration)
  - `azure_keyvault`: Azure REST API for vault secrets metadata (not values!)
  - `gcp_secrets`: GCP Secret Manager API
  - `venafi`: Venafi TPP/Cloud API (certificates, expiry, compliance)
  - `digicert`: CertCentral REST API (orders, certificates, expiry)
  - `ivanti`: Ivanti Patch API (devices, patches, compliance)
- [ ] **Step 2:** Create all 8 matching normalizers
  - Cert connectors: observation_type="misconfiguration" for expired/expiring certs, "inventory" for valid
  - Patch connectors: observation_type="vulnerability" for missing patches, "inventory" for compliant
  - Secrets connectors: observation_type="inventory" for secrets metadata, "misconfiguration" for rotation overdue
- [ ] **Step 3:** Add all 16 modules to loader.py lists
- [ ] **Step 4:** Verify imports for all 8 connectors + 8 normalizers
- [ ] **Step 5:** Run `pytest tests/ -x -q`
- [ ] **Step 6:** Commit: `feat(connectors): add patch, cert, and secrets mgmt connectors`

### Task 3: Batch 1C — Existing Backlog P1 connectors (7 connectors)

**Files to create:**
- `warlock/connectors/servicenow_grc.py` (ITSM) — C-1
- `warlock/connectors/nightfall.py` (DLP) — C-36
- `warlock/connectors/aws_backup.py` (BACKUP) — C-45
- `warlock/connectors/orca.py` (CSPM) — C-46
- `warlock/connectors/lacework.py` (CSPM) — C-47
- `warlock/connectors/rapid7.py` (SCANNER) — C-52
- `warlock/connectors/crowdstrike_spotlight.py` (SCANNER) — C-53
- Matching normalizers (7 files)

**Modify:** `warlock/pipeline/loader.py` — add 7+7 entries

- [ ] **Step 1:** Create all 7 connectors
- [ ] **Step 2:** Create all 7 normalizers
- [ ] **Step 3:** Add all 14 modules to loader.py lists
- [ ] **Step 4:** Verify imports
- [ ] **Step 5:** Run `pytest tests/ -x -q`
- [ ] **Step 6:** Commit: `feat(connectors): add servicenow_grc, nightfall, aws_backup, orca, lacework, rapid7, crowdstrike_spotlight`

### Task 4: Batch 2A — IAM, MDM, SIEM, Network, GRC connectors (11 connectors)

**Files to create:**
- `warlock/connectors/ping_identity.py` (IAM) — C-2
- `warlock/connectors/onelogin.py` (IAM) — C-3
- `warlock/connectors/workspace_one.py` (MDM) — C-4
- `warlock/connectors/sumo_logic.py` (SIEM) — C-5
- `warlock/connectors/cisco_umbrella.py` (NETWORK) — C-6
- `warlock/connectors/drata.py` (GRC) — C-7
- `warlock/connectors/vanta.py` (GRC) — C-8
- `warlock/connectors/archer.py` (GRC) — C-9
- `warlock/connectors/drata_api.py` (GRC) — C-61
- `warlock/connectors/vanta_api.py` (GRC) — C-62
- `warlock/connectors/secureframe.py` (GRC) — C-63
- Matching normalizers (11 files)

**Modify:** `warlock/pipeline/loader.py`

- [ ] **Step 1:** Create all 11 connectors
- [ ] **Step 2:** Create all 11 normalizers
- [ ] **Step 3:** Add all 22 modules to loader.py
- [ ] **Step 4:** Verify imports
- [ ] **Step 5:** Run `pytest tests/ -x -q`
- [ ] **Step 6:** Commit: `feat(connectors): add iam, mdm, siem, network, grc tier-2 connectors`

### Task 5: Batch 2B — Collaboration, Infrastructure, HRIS connectors (8 connectors)

**Files to create:**
- `warlock/connectors/salesforce.py` (COLLABORATION) — C-10
- `warlock/connectors/teams_compliance.py` (COLLABORATION) — C-55
- `warlock/connectors/zoom.py` (COLLABORATION) — C-56
- `warlock/connectors/smarsh.py` (COLLABORATION) — C-57
- `warlock/connectors/ansible.py` (INFRASTRUCTURE) — C-11
- `warlock/connectors/adp.py` (HRIS) — C-12
- `warlock/connectors/ukg.py` (HRIS) — C-13
- `warlock/connectors/sap_successfactors.py` (HRIS) — C-14
- Matching normalizers (8 files)

**Modify:** `warlock/pipeline/loader.py`

- [ ] **Step 1:** Create all 8 connectors
- [ ] **Step 2:** Create all 8 normalizers
- [ ] **Step 3:** Add to loader.py, verify imports, run pytest
- [ ] **Step 4:** Commit: `feat(connectors): add collab, infra, hris tier-2 connectors`

### Task 6: Batch 2C — AI/ML, Email Security, Supply Chain, API Security connectors (11 connectors)

**Files to create:**
- `warlock/connectors/wandb.py` (AI_ML) — C-15
- `warlock/connectors/vertex_ai.py` (AI_ML) — C-16
- `warlock/connectors/mimecast.py` (EMAIL_SECURITY) — C-17
- `warlock/connectors/chainguard.py` (CONTAINER_SECURITY) — C-24
- `warlock/connectors/syft_grype.py` (CONTAINER_SECURITY) — C-25
- `warlock/connectors/fossa.py` (CODE) — C-26
- `warlock/connectors/snyk_container.py` (CONTAINER_SECURITY) — C-27
- `warlock/connectors/socketdev.py` (CODE) — C-28
- `warlock/connectors/salt_security.py` (CUSTOM) — C-29
- `warlock/connectors/noname.py` (CUSTOM) — C-30
- `warlock/connectors/wallarm.py` (NETWORK) — C-31
- Matching normalizers (11 files)

- [ ] **Step 1:** Create all 11 connectors + normalizers
- [ ] **Step 2:** Add to loader.py, verify imports, run pytest
- [ ] **Step 3:** Commit: `feat(connectors): add ai-ml, email-sec, supply-chain, api-sec connectors`

### Task 7: Batch 2D — Zero Trust, DLP, Backup, CSPM, Privacy, Vuln, Endpoint, Pentest connectors (22 connectors)

This task is large (44 files). Split into 3 sub-tasks for parallel agent dispatch.

#### Task 7A: Zero Trust + DLP + API Security (8 connectors)

**Files to create:**
- `warlock/connectors/fortytwoCrunch.py` (CUSTOM) — C-32
- `warlock/connectors/tailscale.py` (NETWORK) — C-33
- `warlock/connectors/twingate.py` (NETWORK) — C-34
- `warlock/connectors/banyan.py` (NETWORK) — C-35
- `warlock/connectors/code42.py` (DLP) — C-37
- `warlock/connectors/varonis.py` (DLP) — C-38
- `warlock/connectors/bigid.py` (DATA_GOVERNANCE) — C-39
- `warlock/connectors/rubrik_security.py` (DLP) — C-40
- Matching normalizers (8 files)

- [ ] Create all 8 connectors + normalizers, verify imports

#### Task 7B: Backup + CSPM + Privacy (7 connectors)

**Files to create:**
- `warlock/connectors/commvault.py` (BACKUP) — C-41
- `warlock/connectors/rubrik.py` (BACKUP) — C-42
- `warlock/connectors/cohesity.py` (BACKUP) — C-43
- `warlock/connectors/druva.py` (BACKUP) — C-44
- `warlock/connectors/ermetic.py` (CSPM) — C-48
- `warlock/connectors/trustarc.py` (GRC) — C-49
- `warlock/connectors/cookiebot.py` (CUSTOM) — C-50
- Matching normalizers (7 files)

- [ ] Create all 7 connectors + normalizers, verify imports

#### Task 7C: Privacy + Vuln + Endpoint + Pentest (7 connectors)

**Files to create:**
- `warlock/connectors/osano.py` (CUSTOM) — C-51
- `warlock/connectors/vulcan.py` (SCANNER) — C-54
- `warlock/connectors/tanium.py` (EDR) — C-58
- `warlock/connectors/automox.py` (MDM) — C-59
- `warlock/connectors/fleet.py` (MDM) — C-60
- `warlock/connectors/cobalt.py` (CUSTOM) — pentest
- `warlock/connectors/hackerone.py` (CUSTOM) — pentest
- Matching normalizers (7 files)

- [ ] Create all 7 connectors + normalizers, verify imports

#### Task 7 Merge

- [ ] Add all 44 modules to loader.py (one agent owns loader.py)
- [ ] Run `pytest tests/ -x -q`
- [ ] Commit: `feat(connectors): add zero-trust, dlp, backup, cspm, privacy, vuln, endpoint, pentest connectors`

### Task 8: Batch 3 — Tier 3 connectors (12 connectors)

**Note:** `plextrac` is listed under Batch 2 pentest platforms in the spec (alongside cobalt/hackerone) but is placed here in Batch 3 since it is P3 priority. All three pentest connectors are implemented — just across different batches.

**Files to create:**
- `warlock/connectors/linode.py` (CLOUD) — C-18
- `warlock/connectors/hetzner.py` (CLOUD) — C-19
- `warlock/connectors/logrhythm.py` (SIEM) — C-20
- `warlock/connectors/barracuda.py` (NETWORK) — C-21
- `warlock/connectors/f5.py` (NETWORK) — C-22
- `warlock/connectors/paylocity.py` (HRIS) — C-23
- `warlock/connectors/kubecost.py` (OBSERVABILITY) — C-64
- `warlock/connectors/infracost.py` (OBSERVABILITY) — C-65
- `warlock/connectors/spotio.py` (CLOUD) — C-66
- `warlock/connectors/manageengine.py` (ITSM)
- `warlock/connectors/ivanti_patch.py` (MDM)
- `warlock/connectors/plextrac.py` (CUSTOM) — pentest
- Matching normalizers (12 files)

- [ ] **Step 1:** Create all 12 connectors + normalizers
- [ ] **Step 2:** Add all 24 modules to loader.py, verify imports, run pytest
- [ ] **Step 3:** Commit: `feat(connectors): add tier-3 connectors (cloud, siem, network, hris, observability)`

### Task 9: Phase 1 Final Verification

- [ ] **Step 1:** Run `pytest tests/ -x -q` — show full output
- [ ] **Step 2:** Count connectors: `ls warlock/connectors/*.py | grep -v __init__ | grep -v __pycache__ | grep -v base.py | grep -v webhook.py | wc -l` — expect 165 (81 existing + 84 new)
- [ ] **Step 3:** Verify every new connector imports cleanly:
  ```bash
  python -c "
  from warlock.pipeline.loader import _CONNECTOR_MODULES, _NORMALIZER_MODULES
  import importlib
  for m in _CONNECTOR_MODULES + _NORMALIZER_MODULES:
      importlib.import_module(m)
  print(f'All {len(_CONNECTOR_MODULES)} connectors and {len(_NORMALIZER_MODULES)} normalizers loaded OK')
  "
  ```
- [ ] **Step 4:** Show pytest output to user before proceeding to Phase 2

---

# PHASE 2: Workflow CLI Modules (12 new modules)

Each CLI module follows the same pattern:
1. Create `warlock/cli/<domain>_cmd.py`
2. Import `cli, console, _error, _get_actor` from `warlock.cli`
3. Use `@cli.group()` for domains with subcommands, `@cli.command()` for flat commands
4. Query existing models via `from warlock.db.engine import get_session, init_db`
5. Render with Rich tables
6. Add `--format json` where specified
7. Register via import in `warlock/cli/__init__.py`

## CLI Module Template

```python
"""<Domain> commands: <list of commands>."""

from __future__ import annotations

import json as _json

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


@cli.group()
def <domain>() -> None:
    """<Domain description>."""


@<domain>.command("list")
@click.option("--status", "-s", default=None, help="Filter by status")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
def <domain>_list(status: str | None, limit: int, fmt: str) -> None:
    """List <items>."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import <Model>

    init_db()
    with get_session() as session:
        q = session.query(<Model>)
        if status:
            q = q.filter(<Model>.status == status)
        rows = q.order_by(<Model>.created_at.desc()).limit(limit).all()

        if fmt == "json":
            console.print(_json.dumps([{"id": r.id, "status": r.status} for r in rows], indent=2, default=str))
            return

        table = Table(title="<Items>")
        table.add_column("ID", style="cyan", max_width=8)
        table.add_column("Status")
        for r in rows:
            table.add_row(r.id[:8], r.status or "—")
        console.print(table)
```

### Task 10: Incidents CLI (`warlock/cli/incidents_cmd.py`)

**Files:**
- Create: `warlock/cli/incidents_cmd.py`
- Modify: `warlock/cli/__init__.py` (add import)

**Models used:** Check `warlock/db/models.py` for incident-related models. If no `Incident` model exists, use `Issue` with classification/severity fields or create commands that work with the available models.

**Commands (~11):**
- `warlock incidents create`, `list`, `show`, `update`, `close`
- `warlock incidents timeline`, `add-event`, `report`, `metrics`
- `warlock incidents link`, `responders`

- [ ] **Step 1:** Read `warlock/db/models.py` for incident-related models (Issue, ControlResult, AuditEntry)
- [ ] **Step 2:** Create `incidents_cmd.py` with `@cli.group("incidents")` and all 11 commands
- [ ] **Step 3:** Add `from warlock.cli import incidents_cmd as _incidents_cmd  # noqa: F401, E402` to `__init__.py`
- [ ] **Step 4:** Verify: `python -c "from warlock.cli import cli; print('incidents' in [c for c in cli.list_commands(click.Context(cli))])"`
- [ ] **Step 5:** Run `pytest tests/ -x -q`
- [ ] **Step 6:** Commit: `feat(cli): add warlock incidents command group`

### Task 11: Evidence CLI (`warlock/cli/evidence_cmd.py`)

**Models used:** `EvidenceRequest`, `AuditEntry` (hash chain), `ControlResult`

**Commands (~17):**
- `warlock evidence list`, `show`, `attach`, `package`, `chain`, `verify`
- `warlock evidence freshness`, `gaps`, `export`, `stats`, `timeline`
- `warlock evidence requests list`, `create`, `assign`, `fulfill`, `import`, `overdue`

- [ ] **Step 1:** Read `warlock/workflows/evidence_vault.py` for evidence patterns
- [ ] **Step 2:** Create `evidence_cmd.py` with `@cli.group("evidence")` and nested `@evidence.group("requests")`
- [ ] **Step 3:** Register in `__init__.py`, verify, run pytest
- [ ] **Step 4:** Commit: `feat(cli): add warlock evidence command group`

### Task 12: Attestations CLI (`warlock/cli/attestations_cmd.py`)

**Models used:** `Attestation`

**Commands (~8):** `list`, `create`, `show`, `sign`, `overdue`, `expiring`, `report`, `history`

- [ ] **Step 1:** Read `warlock/workflows/attestations.py`
- [ ] **Step 2:** Create `attestations_cmd.py`
- [ ] **Step 3:** Register, verify, pytest, commit: `feat(cli): add warlock attestations command group`

### Task 13: Privacy CLI (`warlock/cli/privacy_cmd.py`)

**Models used:** `DataSilo`, `AuditEntry`, plus workflow state from `warlock/workflows/gdpr.py`

**Commands (~17):**
- `warlock privacy dsar create/list/show/fulfill/escalate/overdue`
- `warlock privacy breach create/show/notify/status`
- `warlock privacy data-map`, `impact-assess`, `ropa`, `transfers list`, `transfers validate`

- [ ] **Step 1:** Read `warlock/workflows/gdpr.py` for DSAR/breach patterns
- [ ] **Step 2:** Create `privacy_cmd.py` with `@cli.group("privacy")` and nested groups `dsar`, `breach`, `transfers`
- [ ] **Step 3:** Register, verify, pytest, commit: `feat(cli): add warlock privacy command group`

### Task 14: Access Reviews CLI (`warlock/cli/access_review_cmd.py`)

**Commands (~7):** `create`, `list`, `show`, `certify`, `revoke`, `report`, `overdue`

- [ ] Create `access_review_cmd.py`, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock access-review command group`

### Task 15: Change Management CLI (`warlock/cli/change_mgmt_cmd.py`)

**Models used:** `ChangeEvent`

**Commands (~9):** `list`, `show`, `create`, `approve`, `reject`, `implement`, `emergency`, `report`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock changes command group`

### Task 16: Exceptions CLI (`warlock/cli/exceptions_cmd.py`)

**Models used:** `PolicyOverride` (or similar exception model)

**Commands (~6):** `list`, `create`, `show`, `renew`, `expiring`, `report`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock exceptions command group`

### Task 17: Calendar CLI (`warlock/cli/calendar_cmd.py`)

**Commands (~5):** `list`, `add`, `overdue`, `next`, `export`

Cross-domain aggregation — queries POAMs, EvidenceRequests, Attestations, PolicyOverrides for due dates.

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock calendar command group`

### Task 18: Audit Engagements CLI (`warlock/cli/audit_engagement_cmd.py`)

**Models used:** `AuditEngagement`, `ExternalAuditor`, `AuditComment`

**Commands (~8):** `engagement create/list/show/status/package`, `findings import`, `corrective-actions`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock audit engagement commands`

### Task 19: Control Tests CLI (`warlock/cli/control_tests_cmd.py`)

**Commands (~7):** `schedule`, `schedule-set`, `execute`, `due`, `history`, `report`, `gaps`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock control-tests command group`

### Task 20: Training CLI (`warlock/cli/training_cmd.py`)

**Commands (~4):** `status`, `overdue`, `campaigns list`, `report`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock training command group`

### Task 21: BCP/DR CLI (`warlock/cli/bcp_cmd.py`)

**Models used:** `SystemProfile` (criticality, RTO/RPO)

**Commands (~6):** `systems`, `bia`, `dr-test schedule/execute/results/report`

- [ ] Create with `@cli.group("bcp")` and nested `@bcp.group("dr-test")`
- [ ] Register, verify, pytest
- [ ] Commit: `feat(cli): add warlock bcp command group`

### Task 22: Phase 2 Final Verification

- [ ] **Step 1:** Run `pytest tests/ -x -q` — show full output
- [ ] **Step 2:** Verify all 12 new CLI groups register:
  ```bash
  python -c "
  import click
  from warlock.cli import cli
  ctx = click.Context(cli)
  cmds = sorted(cli.list_commands(ctx))
  print(f'Total top-level commands/groups: {len(cmds)}')
  for c in cmds: print(f'  {c}')
  "
  ```
- [ ] **Step 3:** Show output to user before proceeding to Phase 3

---

# PHASE 3: Expand Existing CLI Domains (~200 new commands)

### Task 23: Connectors CLI (`warlock/cli/connectors_cmd.py`) — ~23 commands

**Commands:** `list`, `show`, `test`, `test-all`, `enable`, `disable`, `status`, `history`, `schema`, `validate`, `validate-all`, `credentials`, `credentials-check`, `collect`, `collect-all`, `stats`, `event-types`, `compare`, `export`, `import`, `health`, `schedule`, `errors`

Queries `ConnectorRegistry` and `ConnectorRun` model.

- [ ] Create `connectors_cmd.py`, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock connectors management commands`

### Task 24: Assertions CLI (`warlock/cli/assertions_cmd.py`) — ~12 commands

**Commands:** `list`, `show`, `run`, `run-all`, `test`, `bindings`, `bindings-for`, `coverage`, `stats`, `history`, `failures`, `explain`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock assertions command group`

### Task 25: Findings CLI (`warlock/cli/findings_cmd.py`) — ~15 commands

**Models used:** `Finding`

**Commands:** `list`, `show`, `search`, `timeline`, `stats`, `suppress`, `unsuppress`, `annotate`, `export`, `deduplicate`, `trending`, `by-connector`, `by-control`, `aging`, `sla`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock findings command group`

### Task 26: Frameworks CLI (`warlock/cli/frameworks_cmd.py`) — ~20 commands

**Commands:** `list`, `show`, `controls`, `compare`, `crosswalk`, `coverage`, `gaps`, `heatmap`, `stats`, `export`, `baselines list/show/apply`, `inherited list/show`, `event-types`, `connectors`, `calendar`, `inheritance report`

- [ ] Create with nested groups `baselines` and `inherited`
- [ ] Register, verify, pytest
- [ ] Commit: `feat(cli): add warlock frameworks command group`

### Task 27: Policies CLI (`warlock/cli/policies_opa_cmd.py`) — ~15 commands

**Commands:** `list`, `show`, `evaluate`, `test`, `test-all`, `coverage`, `stats`, `check`, `diff`, `search`, `unused`, `export`, `lifecycle list/review-due/acknowledge`

Note: Use a different module name than existing `policy_cmd.py` to avoid conflict.

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock policies (OPA) command group`

### Task 28: Audit Trail CLI (`warlock/cli/audit_trail_cmd.py`) — ~11 commands

**Models used:** `AuditEntry` (hash-chained)

**Commands:** `list`, `show`, `verify`, `search`, `timeline`, `stats`, `export`, `integrity-report`, `tamper-detect`, `retention-status`, `user-activity`

Note: Name the group `audit-trail` or extend existing audit if compatible.

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock audit-trail command group`

### Task 29: Users/RBAC CLI (`warlock/cli/users_cmd.py`) — ~14 commands

**Models used:** `User`, `APIKey`

**Commands:** `users list/show/create/update/deactivate/sessions/permissions/sod-check/audit-log`, `roles list/show/create`, `scopes list/assign`

- [ ] Create with nested groups `roles` and `scopes`
- [ ] Register, verify, pytest
- [ ] Commit: `feat(cli): add warlock users command group`

### Task 30: Reports CLI (`warlock/cli/reports_cmd.py`) — ~16 commands

Cross-domain reporting — queries multiple models.

**Commands:** `executive`, `compliance`, `trend`, `risk`, `connector-health`, `audit-readiness`, `generate`, `templates list`, `schedule`, `history`, `board`, `kri`, `kpi`, `conmon`, `sla`, `attestation-summary`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock reports command group`

### Task 31: Vendors/TPRM CLI (`warlock/cli/vendors_cmd.py`) — ~16 commands

**Models used:** `Vendor`

**Commands:** `list`, `show`, `create`, `assess`, `questionnaire`, `risk-score`, `history`, `export`, `reassess-due`, `contracts`, `incidents`, `concentration`, `soc2-review`, `fourth-party`, `offboard`, `sla`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock vendors command group`

### Task 32: Integrations + Notifications CLI (`warlock/cli/integrations_cmd.py`) — ~10 commands

**Commands:** `integrations list/configure/test/status`, `notifications list/configure/test/rules list/rules create/rules delete`

- [ ] Create with nested `notifications` group
- [ ] Register, verify, pytest
- [ ] Commit: `feat(cli): add warlock integrations command group`

### Task 33: OSCAL CLI (`warlock/cli/oscal_cmd.py`) — ~8 commands

**Commands:** `catalogs list/show`, `profiles list/show`, `assessment-results`, `ssp`, `poam`, `validate`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock oscal command group`

### Task 34: Pipeline Extensions (`warlock/cli/pipeline_ext_cmd.py`) — ~11 commands

**Files:**
- Create: `warlock/cli/pipeline_ext_cmd.py`
- Modify: `warlock/cli/__init__.py` (add import)

**Collision analysis:** Existing `pipeline.py` registers `init`, `collect`, `ingest` as flat `@cli.command()` commands (not under a group), plus a `scheduler` group. There is NO existing `pipeline` group. This task creates a new `@cli.group("pipeline")` for management commands. The existing flat commands (`init`, `collect`, `ingest`) remain untouched and accessible directly as `warlock init`, `warlock collect`, `warlock ingest`. The new group is `warlock pipeline status|history|run|...`.

**Commands:** `status`, `history`, `run`, `verify-chain`, `stats`, `errors`, `schedule show/set`, `replay`, `compare`, `hash-verify`

- [ ] Verify no Click name collision: `pipeline` group name does not conflict with existing flat commands
- [ ] Create `pipeline_ext_cmd.py` with `@cli.group("pipeline")`, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock pipeline management commands`

### Task 35: Vulnerability Lifecycle CLI (`warlock/cli/vulns_cmd.py`) — ~8 commands

**Commands:** `dashboard`, `sla-breach`, `trends`, `accept`, `aging`, `by-scanner`, `remediation-rate`, `report`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock vulns command group`

### Task 36: ConMon CLI (`warlock/cli/conmon_cmd.py`) — ~5 commands

**Commands:** `status`, `monthly-report`, `deviation create`, `significant-change create`, `checklist`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock conmon command group`

### Task 37: SoD CLI (`warlock/cli/sod_cmd.py`) — ~3 commands

**Commands:** `analyze`, `conflicts`, `matrix`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock sod command group`

### Task 38: POA&M Milestones (`warlock/cli/poam_cmd.py`) — ~3 commands

**Files:**
- Create: `warlock/cli/poam_cmd.py`
- Modify: `warlock/cli/__init__.py` (add import)

**Commands:** `warlock poam milestones <poam_id>`, `warlock poam milestone-update <poam_id> <milestone_id>`, `warlock poam deviation <poam_id>`

**Important:** The existing `poams` command (plural, flat `@cli.command("poams")` in governance.py) is a LIST command and must NOT be modified. This new module creates a separate `@cli.group("poam")` (singular) for milestone management. Users will have both `warlock poams` (list) and `warlock poam milestones/milestone-update/deviation` (management). The different names (`poams` vs `poam`) avoid Click collision.

- [ ] Create `poam_cmd.py` with `@cli.group("poam")` and 3 subcommands
- [ ] Register in `__init__.py`, verify, run pytest
- [ ] Commit: `feat(cli): add warlock poam milestone commands`

### Task 39: Terraform CLI (`warlock/cli/terraform_cmd.py`) — ~6 commands

**Commands:** `modules list/show`, `validate`, `plan`, `drift`, `compliance`

- [ ] Create, register, verify, pytest
- [ ] Commit: `feat(cli): add warlock terraform command group`

### Task 40: Phase 3 Final Verification

- [ ] **Step 1:** Run `pytest tests/ -x -q` — show full output
- [ ] **Step 2:** Count all leaf commands:
  ```bash
  python -c "
  import click
  from warlock.cli import cli
  def count_leaves(group, prefix=''):
      ctx = click.Context(group)
      total = 0
      for name in group.list_commands(ctx):
          cmd = group.get_command(ctx, name)
          if isinstance(cmd, click.Group):
              total += count_leaves(cmd, f'{prefix}{name} ')
          else:
              total += 1
      return total
  print(f'Total leaf commands: {count_leaves(cli)}')
  "
  ```
- [ ] **Step 3:** Show output to user

---

# PHASE 4: Final Verification

### Task 41: Full QA + Reporting

- [ ] **Step 1:** Run `./scripts/qa.sh` — show complete output
- [ ] **Step 2:** Show total connector count:
  ```bash
  ls warlock/connectors/*.py | grep -v __init__ | grep -v __pycache__ | grep -v base.py | grep -v webhook.py | wc -l
  ```
- [ ] **Step 3:** Show total leaf command count (script from Task 40)
- [ ] **Step 4:** List every new file created (`git status --short | grep '^??' | wc -l` and full list)
- [ ] **Step 5:** List every modified file (`git diff --name-only` — should only be `warlock/cli/__init__.py` and `warlock/pipeline/loader.py`)
- [ ] **Step 6:** Show all output to user and ask: "Ready to push?"
- [ ] **DO NOT PUSH** — wait for explicit approval

---

## Parallelization Strategy

### Safe to parallelize (no file overlap):
- **Connectors within a batch** — each connector is its own file, zero cross-deps
- **CLI modules in Phase 2 and 3** — each is its own file, independent

### Must serialize:
- **`warlock/pipeline/loader.py`** — all connector batches add entries to the same two lists. Each batch must update loader.py sequentially, or one agent owns loader.py and merges entries after all connectors are built.
- **`warlock/cli/__init__.py`** — all CLI modules add imports to the same file. Same serialization constraint.

### Recommended agent dispatch pattern:
1. **Phase 1:** Dispatch up to 4 connector-building agents in parallel (one per batch), each creating connector + normalizer files. ONE designated agent (or the coordinator) owns `loader.py` and adds all entries after each batch completes.
2. **Phase 2-3:** Dispatch up to 4 CLI-building agents in parallel, each owning 3-4 CLI modules. ONE agent owns `__init__.py` and adds imports after each module is verified.

## File Count Summary

| Category | New Files | Modified Files |
|----------|-----------|----------------|
| Connectors | 84 | 0 |
| Normalizers | 84 | 0 |
| CLI modules | ~18 | 1 (`__init__.py`) |
| Pipeline loader | 0 | 1 (`loader.py`) |
| **Total** | **~186** | **2** |
