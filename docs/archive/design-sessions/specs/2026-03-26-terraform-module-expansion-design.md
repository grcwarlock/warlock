# Terraform Module Expansion — Full Design Spec

**Date:** 2026-03-26
**Status:** Implemented (Phases 1-4 complete, Phase 5 pending)
**Scope:** Remediation modules (all clouds), deployment modules (Warlock itself), closed-loop remediation engine

---

## 1. Problem Statement

Warlock has 351 connectors ingesting findings from 40+ source types across 15+ cloud providers. But only 12 Terraform modules exist (8 AWS, 2 Azure, 2 GCP), all focused on account-level hardening. This creates three gaps:

1. **Remediation gap**: Connectors detect issues Warlock cannot fix. No IaC exists for encryption, networking, storage, or compute hardening on Alibaba, Huawei, OCI, IBM Cloud, DigitalOcean, Cloudflare, OVH, Scaleway, Hetzner, Linode, Heroku, Render, Netlify, or Vercel.
2. **Deployment gap**: No IaC to deploy Warlock itself. The DEPLOYMENT_GUIDE.md is manual (Python + PostgreSQL + Redis + OPA on bare metal).
3. **Closed-loop gap**: The existing `warlock_evidence` self-registration POSTs to `/api/v1/evidence` which doesn't exist yet. Remediation is generate-only (produces commands), not apply-capable.

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Module organization | Domain-first | GRC users think in control families, not cloud providers |
| Cloud coverage | All 15+ providers | Every CLOUD-type connector gets matching remediation modules |
| Deployment model | Container + cloud-native per provider | Dockerfile + ECS/Container Apps/Cloud Run/etc. |
| Remediation loop | Closed-loop (detect → plan → apply → verify) | Full GRC automation, not just reporting |
| Limited providers | Full modules with stubs | Explicit "provider limitation" markers, not silent gaps |

## 3. Architecture

### 3.1 Directory Structure

```
terraform/
  modules/
    # ── REMEDIATION ENGINE (new) ──────────────────────────
    remediation-engine/
      main.tf              # Terraform Cloud workspace + webhook
      variables.tf
      outputs.tf
      lambda/              # Bridge: Warlock API → Terraform Cloud API
        handler.py
      README.md

    # ── WARLOCK DEPLOYMENT (new) ──────────────────────────
    deploy/
      container-image/     # Dockerfile, docker-compose.yml
        Dockerfile
        docker-compose.yml
        .dockerignore
        nginx.conf         # Reverse proxy
        README.md
      aws-ecs/             # ECS Fargate + RDS + ElastiCache + ALB
      aws-eks/             # EKS + RDS + ElastiCache + Ingress
      azure-container-apps/# Container Apps + Flexible Server + Redis Cache
      gcp-cloud-run/       # Cloud Run + Cloud SQL + Memorystore
      digitalocean-app/    # App Platform + Managed DB + Redis
      kubernetes-helm/     # Helm chart (any K8s cluster)
      README.md

    # ── REMEDIATION DOMAINS (reorganized + new) ──────────
    encryption/
      aws-kms/             # ← existing aws/kms-baseline, enhanced
      azure-keyvault/      # ← existing azure/key-vault-baseline, enhanced
      gcp-kms/             # ← existing gcp/kms-baseline, enhanced
      alibaba-kms/         # NEW
      oci-vault/           # NEW
      ibm-key-protect/     # NEW
      huawei-kms/          # NEW
      digitalocean-spaces-encryption/  # NEW (limited — stub)
      cloudflare-ssl/      # NEW
      README.md

    logging/
      aws-cloudtrail/      # ← existing aws/cloudtrail-org, enhanced
      aws-config-rules/    # ← existing aws/config-rules, enhanced
      azure-activity-log/  # ← existing azure/secure-subscription-baseline (logging portion)
      gcp-audit-log/       # ← existing gcp/secure-project-baseline (logging portion)
      alibaba-actiontrail/ # NEW
      oci-audit/           # NEW
      ibm-activity-tracker/# NEW
      huawei-cts/          # NEW
      digitalocean-monitoring/ # NEW
      cloudflare-audit-log/# NEW
      ovh-logs/            # NEW (limited — stub)
      scaleway-cockpit/    # NEW
      hetzner-audit/       # NEW (limited — stub, no native audit API)
      README.md

    networking/
      aws-vpc/             # ← existing aws/compliant-vpc, enhanced
      azure-vnet/          # NEW
      gcp-vpc/             # NEW
      alibaba-vpc/         # NEW
      oci-vcn/             # NEW
      ibm-vpc/             # NEW
      huawei-vpc/          # NEW
      digitalocean-vpc/    # NEW
      cloudflare-waf/      # NEW
      ovh-vrack/           # NEW (limited)
      scaleway-vpc/        # NEW
      hetzner-firewall/    # NEW
      linode-firewall/     # NEW
      kubernetes-network-policy/ # NEW
      README.md

    iam/
      aws-iam/             # ← existing aws/iam-baseline, enhanced
      azure-entra/         # NEW
      gcp-iam/             # NEW
      alibaba-ram/         # NEW
      oci-iam/             # NEW
      ibm-iam/             # NEW
      huawei-iam/          # NEW
      digitalocean-teams/  # NEW (limited)
      cloudflare-access/   # NEW
      kubernetes-rbac/     # NEW
      README.md

    storage/
      aws-s3/              # NEW
      azure-storage/       # NEW
      gcp-gcs/             # NEW
      alibaba-oss/         # NEW
      oci-object-storage/  # NEW
      ibm-cos/             # NEW
      huawei-obs/          # NEW
      digitalocean-spaces/ # NEW
      cloudflare-r2/       # NEW
      ovh-object-storage/  # NEW (limited)
      scaleway-object-storage/ # NEW
      hetzner-storage-box/ # NEW (limited — stub)
      linode-object-storage/ # NEW
      README.md

    compute/
      aws-ec2/             # NEW
      aws-ecs/             # NEW (task hardening, not Warlock deploy)
      aws-lambda/          # NEW
      azure-vm/            # NEW
      azure-functions/     # NEW
      gcp-compute/         # NEW
      gcp-cloud-functions/ # NEW
      alibaba-ecs/         # NEW
      oci-compute/         # NEW
      ibm-vsi/             # NEW
      huawei-ecs/          # NEW
      digitalocean-droplet/# NEW
      hetzner-server/      # NEW
      linode-instance/     # NEW
      scaleway-instance/   # NEW
      kubernetes-deployment/ # NEW
      README.md

    container/
      aws-ecr/             # NEW
      azure-acr/           # NEW
      gcp-gar/             # NEW (Artifact Registry)
      alibaba-cr/          # NEW
      oci-container-registry/ # NEW
      kubernetes-admission/# NEW (OPA Gatekeeper / Kyverno)
      kubernetes-pod-security/ # NEW
      README.md

    threat-detection/
      aws-guardduty/       # ← existing aws/guardduty-org, enhanced
      aws-security-hub/    # NEW
      azure-defender/      # NEW
      gcp-scc/             # NEW (Security Command Center)
      alibaba-security-center/ # NEW
      oci-cloud-guard/     # NEW
      ibm-security-advisor/ # NEW
      README.md

    drift-detection/
      aws-drift/           # ← existing aws/drift-detector, enhanced
      azure-drift/         # NEW
      gcp-drift/           # NEW
      multi-cloud-drift/   # NEW (generic Terraform state comparison)
      README.md

    account-baseline/
      aws-account/         # ← existing aws/secure-account-baseline, enhanced
      aws-govcloud/        # NEW (GovCloud-specific baseline, maps to aws_govcloud connector)
      azure-subscription/  # NEW (expanded from secure-subscription-baseline)
      gcp-project/         # NEW (expanded from secure-project-baseline)
      alibaba-account/     # NEW
      oci-tenancy/         # NEW
      ibm-account/         # NEW
      huawei-account/      # NEW
      README.md

    database/
      aws-rds/             # NEW
      azure-sql/           # NEW
      gcp-cloud-sql/       # NEW
      mongodb-atlas/       # NEW
      digitalocean-db/     # NEW
      README.md

    secrets/
      aws-secrets-manager/ # NEW
      azure-keyvault-secrets/ # NEW (secrets-specific, separate from encryption)
      gcp-secret-manager/  # NEW
      hashicorp-vault/     # NEW
      README.md

    certificate/
      aws-acm/             # NEW
      azure-app-gateway-cert/ # NEW
      gcp-certificate-manager/ # NEW
      cloudflare-cert/     # NEW
      README.md

    platform-paas/
      heroku-app/          # NEW (limited — security headers, add-ons)
      render-service/      # NEW (limited — env var security, auto-scaling)
      netlify-site/        # NEW (limited — headers, redirects, env security)
      vercel-project/      # NEW (limited — env vars, headers, deployment protection)
      supabase-project/    # NEW (limited — RLS policies, auth config)
      README.md

    # ── SHARED LIBRARIES ──────────────────────────────────
    _shared/
      warlock-registration/  # Reusable self-registration submodule
        main.tf
        variables.tf
        outputs.tf
      warlock-remediation/   # Reusable remediation-trigger submodule
        main.tf
        variables.tf
        outputs.tf
      tags/                  # Standard tagging/labeling
        main.tf
        variables.tf
        outputs.tf
```

### 3.2 Module Count Summary

| Domain | Modules | Providers Covered |
|--------|---------|-------------------|
| encryption | 9 | AWS, Azure, GCP, Alibaba, OCI, IBM, Huawei, DO, Cloudflare |
| logging | 13 | AWS(2), Azure, GCP, Alibaba, OCI, IBM, Huawei, DO, Cloudflare, OVH, Scaleway, Hetzner |
| networking | 14 | AWS, Azure, GCP, Alibaba, OCI, IBM, Huawei, DO, Cloudflare, OVH, Scaleway, Hetzner, Linode, K8s |
| iam | 10 | AWS, Azure, GCP, Alibaba, OCI, IBM, Huawei, DO, Cloudflare, K8s |
| storage | 13 | AWS, Azure, GCP, Alibaba, OCI, IBM, Huawei, DO, Cloudflare, OVH, Scaleway, Hetzner, Linode |
| compute | 16 | AWS(3), Azure(2), GCP(2), Alibaba, OCI, IBM, Huawei, DO, Hetzner, Linode, Scaleway, K8s |
| container | 7 | AWS, Azure, GCP, Alibaba, OCI, K8s(2) |
| threat-detection | 7 | AWS(2), Azure, GCP, Alibaba, OCI, IBM |
| drift-detection | 4 | AWS, Azure, GCP, Multi-cloud |
| account-baseline | 8 | AWS, AWS GovCloud, Azure, GCP, Alibaba, OCI, IBM, Huawei |
| database | 5 | AWS, Azure, GCP, MongoDB Atlas, DO |
| secrets | 4 | AWS, Azure, GCP, HashiCorp |
| certificate | 4 | AWS, Azure, GCP, Cloudflare |
| platform-paas | 5 | Heroku, Render, Netlify, Vercel, Supabase |
| deploy (Warlock) | 7 | Container image, AWS ECS, AWS EKS, Azure Container Apps, GCP Cloud Run, DO App Platform, K8s Helm |
| remediation-engine | 1 | Cross-cloud |
| _shared | 3 | Cross-cloud |
| **TOTAL** | **127** | **15+ cloud providers + Kubernetes + PaaS platforms** |

> **Actual counts (post-implementation):** 127 module directories, 499 .tf files, 13 Helm chart files. 125 Terraform modules validate clean + 1 Helm chart + 1 container image.

### 3.3 Migration of Existing 12 Modules

| Current Location | New Location | Changes |
|-----------------|-------------|---------|
| aws/kms-baseline | encryption/aws-kms | + remediation trigger, + connector registration |
| aws/cloudtrail-org | logging/aws-cloudtrail | + remediation trigger |
| aws/config-rules | logging/aws-config-rules | + remediation trigger |
| aws/compliant-vpc | networking/aws-vpc | + remediation trigger |
| aws/iam-baseline | iam/aws-iam | + remediation trigger |
| aws/guardduty-org | threat-detection/aws-guardduty | + remediation trigger |
| aws/drift-detector | drift-detection/aws-drift | + remediation trigger |
| aws/secure-account-baseline | account-baseline/aws-account | + remediation trigger, refactor to compose domain modules |
| azure/key-vault-baseline | encryption/azure-keyvault | + remediation trigger |
| azure/secure-subscription-baseline | Split: logging/azure-activity-log + account-baseline/azure-subscription | Decompose into focused modules |
| gcp/kms-baseline | encryption/gcp-kms | + remediation trigger |
| gcp/secure-project-baseline | Split: logging/gcp-audit-log + account-baseline/gcp-project | Decompose into focused modules |

## 4. Remediation Engine (Closed Loop)

### 4.1 Flow

```
Connector (detect) → Finding → ControlResult (non_compliant)
    ↓
Remediation API (generate plan)
    ↓
Remediation Engine (trigger Terraform)
    ↓                          ↓
Terraform Cloud workspace     OR   Local Terraform apply
    ↓                          ↓
Plan → (optional approval) → Apply
    ↓
Self-registration POST → /api/v1/evidence
    ↓
Warlock verifies fix → ControlResult (compliant)
    ↓
Remediation closed
```

### 4.2 Components

**a) `/api/v1/evidence` endpoint (NEW — required)**

The endpoint all Terraform modules POST to. Currently referenced but doesn't exist.

```python
POST /api/v1/evidence
{
  "module": "encryption/aws-kms",
  "resource_id": "arn:aws:kms:us-east-1:123456789:key/abc",
  "control_ids": ["SC-12", "SC-28"],
  "attributes": { "key_rotation_enabled": true, ... },
  "action": "provision" | "remediate" | "verify"
}
```

Actions:
- `provision`: Module was applied (new infra). Create evidence record, link to controls.
- `remediate`: Module was applied as a fix. Update Remediation record status → verification.
- `verify`: Module ran a check-only. Update ControlResult with latest state.

**b) Remediation trigger submodule (`_shared/warlock-remediation/`)**

Every domain module includes this submodule. It:
1. Accepts a `remediation_id` variable (optional — set when triggered by Warlock)
2. On successful apply, POSTs evidence with `action: "remediate"`
3. On plan-only (dry run), POSTs with `action: "verify"`

**c) Remediation engine module (`remediation-engine/`)**

A Lambda/Cloud Function that bridges Warlock → Terraform Cloud:
1. Warlock API calls engine with: finding, target module, variables
2. Engine creates a Terraform Cloud run with those variables
3. Terraform Cloud applies the module
4. Module self-registers evidence back to Warlock
5. Warlock connector re-scans to verify

### 4.3 Approval Gate

Remediation applies can be:
- **Auto-approved**: Low-risk changes (tag fixes, enabling logging, enabling encryption on new resources)
- **Manual approval**: High-risk changes (security group modifications, IAM policy changes, network topology)
- **Dry-run only**: Generates plan, human reviews, then approves via Warlock UI

The risk classification is stored per-module in a `remediation.tf` metadata file:

```hcl
# remediation.tf (in every module)
locals {
  warlock_remediation = {
    risk_level    = "low"   # low | medium | high | critical
    auto_approve  = true    # Can Warlock auto-apply without human approval?
    rollback_safe = true    # Can this be safely reverted?
    control_ids   = ["SC-12", "SC-28"]  # NIST 800-53 control IDs this module addresses
    connectors    = ["aws", "aws_secrets", "guardduty"]  # Warlock connectors that detect issues this fixes
  }
}
```

## 5. Deployment Modules (Warlock Self-Deploy)

### 5.1 Container Image

```
deploy/container-image/
  Dockerfile           # Multi-stage: builder (deps) → runtime (Python 3.12-slim)
  docker-compose.yml   # Full stack: warlock-api, warlock-worker, postgres, redis, opa
  .dockerignore
  nginx.conf           # Reverse proxy with security headers
  entrypoint.sh        # Migrations + uvicorn/gunicorn
```

The Dockerfile produces a single image used by all cloud-native deploy modules.

### 5.2 Cloud-Native Deploy Modules

Each module provisions:

| Component | What It Deploys |
|-----------|----------------|
| Compute | Warlock API (FastAPI + Gunicorn) |
| Worker | Pipeline scheduler + queue consumer |
| Database | PostgreSQL 15+ (managed) |
| Cache | Redis 7+ (managed) |
| Policy engine | OPA (sidecar or standalone) |
| Load balancer | HTTPS termination, health checks |
| DNS | Optional custom domain |
| Monitoring | Health checks, log aggregation |
| Secrets | All WLK_* env vars in managed secret store |

**Per-provider specifics:**

| Module | Compute | DB | Cache | LB | Secrets |
|--------|---------|-----|-------|-----|---------|
| aws-ecs | Fargate | RDS PostgreSQL | ElastiCache Redis | ALB | Secrets Manager |
| aws-eks | EKS + kubernetes-helm chart | RDS PostgreSQL | ElastiCache Redis | ALB Ingress | Secrets Manager |
| azure-container-apps | Container Apps | Flexible Server | Azure Cache for Redis | Built-in | Key Vault |
| gcp-cloud-run | Cloud Run | Cloud SQL | Memorystore | Cloud Load Balancing | Secret Manager |
| digitalocean-app | App Platform | Managed PostgreSQL | Managed Redis | Built-in | App-level env |
| kubernetes-helm | Helm chart | External (var) | External (var) | Ingress | K8s Secrets / External Secrets |

### 5.3 Helm Chart

The `kubernetes-helm/` module is a full Helm chart that works on any Kubernetes cluster:

```
kubernetes-helm/
  Chart.yaml
  values.yaml
  templates/
    deployment-api.yaml
    deployment-worker.yaml
    service.yaml
    ingress.yaml
    configmap.yaml
    secret.yaml
    hpa.yaml
    pdb.yaml
    serviceaccount.yaml
    networkpolicy.yaml
  charts/              # Optional subcharts
    postgresql/
    redis/
    opa/
```

## 6. Module Conventions

### 6.1 Standard File Layout (Every Module)

```
<domain>/<provider>-<service>/
  main.tf              # Resources
  variables.tf         # Inputs with validation blocks
  outputs.tf           # Outputs
  versions.tf          # terraform/provider version constraints
  remediation.tf       # Warlock remediation metadata (risk, auto-approve, connectors)
  README.md            # Usage, controls addressed, provider limitations
  tests/               # Terraform test files (.tftest.hcl)
    basic.tftest.hcl
```

### 6.2 Standard Variables (All Modules)

```hcl
variable "name_prefix" {
  type        = string
  default     = "warlock"
  description = "Prefix for resource names."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name_prefix))
    error_message = "Must be 2-20 lowercase alphanumeric characters."
  }
}

variable "tags" {   # or "labels" for GCP/Alibaba
  type        = map(string)
  default     = {}
  description = "Tags to apply to all resources."
}

# Warlock integration (all modules)
variable "warlock_api_endpoint" {
  type        = string
  default     = null
  description = "Warlock API base URL. Null disables self-registration."
}

variable "warlock_api_token" {
  type        = string
  default     = null
  sensitive   = true
  description = "Bearer token for Warlock API."
}

variable "warlock_remediation_id" {
  type        = string
  default     = null
  description = "Remediation ID when triggered by closed-loop engine. Null = standalone."
}
```

### 6.3 Standard Tags

All modules apply:

```hcl
locals {
  common_tags = merge(var.tags, {
    ManagedBy      = "warlock"
    Module         = "<domain>/<provider>-<service>"
    Framework      = "NIST-800-53"
    RemediationId  = var.warlock_remediation_id
  })
}
```

### 6.4 Self-Registration (Shared Submodule)

Every module includes `_shared/warlock-registration`:

```hcl
module "warlock_registration" {
  source = "../../_shared/warlock-registration"  # Relative path — all domain modules are at depth 2 (domain/provider-service/)

  enabled          = var.warlock_api_endpoint != null
  api_endpoint     = var.warlock_api_endpoint
  api_token        = var.warlock_api_token
  module_name      = "encryption/aws-kms"
  resource_id      = aws_kms_key.this.arn
  control_ids      = ["SC-12", "SC-28"]
  remediation_id   = var.warlock_remediation_id
  attributes       = { key_rotation = true, deletion_window = var.deletion_window }
}
```

### 6.5 Provider Limitation Markers

For limited providers, modules include:

```hcl
# remediation.tf
locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["AU-2"]
    connectors    = ["hetzner"]
    limitations   = [
      "Hetzner Cloud API does not support native audit logging. This module configures firewall rules only.",
      "Log forwarding requires manual setup of a syslog agent on each server."
    ]
  }
}
```

README.md for stub modules clearly documents:
- What the module CAN do with the provider's Terraform resources
- What it CANNOT do (with explanation of provider limitation)
- Workarounds (manual steps, third-party tools)

## 7. Connector → Module Mapping

This table shows which Warlock connectors detect issues that each domain's modules remediate. This is the core of the closed loop.

| Domain | Connector Source Types | Example: Finding Detected → Module Applied |
|--------|----------------------|---------------------------------------------|
| encryption | CLOUD, CSPM | "KMS key rotation disabled" → `encryption/aws-kms` (enable rotation) |
| logging | CLOUD, CSPM | "CloudTrail not enabled" → `logging/aws-cloudtrail` (enable trail) |
| networking | CLOUD, NETWORK, CSPM | "Security group allows 0.0.0.0/0:22" → `networking/aws-vpc` (restrict SG) |
| iam | CLOUD, IAM, CSPM | "Root account has no MFA" → `iam/aws-iam` (enforce MFA policy) |
| storage | CLOUD, CSPM | "S3 bucket is public" → `storage/aws-s3` (block public access) |
| compute | CLOUD, CSPM | "EC2 IMDSv1 enabled" → `compute/aws-ec2` (enforce IMDSv2) |
| container | CONTAINER_SECURITY, CLOUD | "K8s pod running as root" → `container/kubernetes-pod-security` (enforce PSS) |
| threat-detection | CLOUD | "GuardDuty not enabled" → `threat-detection/aws-guardduty` (enable) |
| drift-detection | INFRASTRUCTURE | "Terraform drift detected" → `drift-detection/aws-drift` (reconcile) |
| database | CLOUD | "RDS not encrypted" → `database/aws-rds` (enable encryption) |
| secrets | CLOUD | "Secret not rotated in 90 days" → `secrets/aws-secrets-manager` (enable rotation) |
| certificate | CLOUD | "Certificate expiring in 7 days" → `certificate/aws-acm` (renew/replace) |

## 8. API Changes Required

### 8.1 New: Evidence Submission Endpoint

```
POST /api/v1/evidence
```

Accepts Terraform module self-registration. Links evidence to findings, control results, and remediations.

### 8.2 Enhanced: Remediation Generate

Extend `/api/v1/remediation/generate` to return:
- The exact Terraform module path to apply
- Pre-populated variable values from the finding
- Risk level and approval requirement

### 8.3 New: Remediation Apply

```
POST /api/v1/remediations/{id}/apply
```

Triggers the remediation engine to apply a Terraform module. Requires approval for high-risk modules.

### 8.4 New: Remediation Verify

```
POST /api/v1/remediations/{id}/re-scan
```

Triggers the matching connector to re-scan the resource and verify the fix.

## 9. Testing Strategy

### 9.1 Per-Module Tests

Every module gets `.tftest.hcl` files testing:
- `terraform validate` passes
- `terraform plan` produces expected resources
- Variable validation catches bad inputs
- Conditional resources (count/for_each) behave correctly

### 9.2 CI Integration

Extend `.github/workflows/compliance-gate.yaml`:
- `terraform validate` on ALL modules (not just existing 12)
- `terraform fmt -check` on ALL modules
- `tflint` with provider-specific rulesets
- Module naming convention enforcement

### 9.3 Integration Tests

For the remediation engine:
- Mock Warlock API accepting evidence POSTs
- Verify self-registration payload schema
- Test remediation trigger → plan → apply → evidence flow
- Test approval gates (auto-approve vs manual)

## 10. Phasing

### Phase 1: Foundation (engine + migration + container)
- Build remediation engine
- Build `/api/v1/evidence` endpoint
- Build `_shared/` submodules
- Migrate existing 12 modules to domain-first structure
- Build container image + docker-compose
- Build Helm chart
- **Result:** Existing modules work in new structure, closed loop operational

### Phase 2: Big Three Expansion (AWS + Azure + GCP)
- Fill all domains for AWS, Azure, GCP
- Build AWS ECS, Azure Container Apps, GCP Cloud Run deploy modules
- **Result:** ~70 modules, full coverage for hyperscalers

### Phase 3: Enterprise Clouds (Alibaba + OCI + IBM + Huawei)
- Fill all domains for enterprise/sovereign providers
- **Result:** ~95 modules

### Phase 4: Platform & Independent Clouds (DO, Cloudflare, Linode, etc.)
- Fill all domains for remaining providers
- Build DigitalOcean App Platform deploy module
- Build platform-paas modules (Heroku, Render, Netlify, Vercel, Supabase)
- **Result:** ~128 modules, full coverage

### Phase 5: Polish & Advanced
- Cross-cloud drift comparison (multi-cloud-drift module)
- Remediation playbooks (pre-built variable sets per finding type)
- Auto-remediation policies (which findings auto-fix without approval)
- Documentation, examples, and registry publishing

## 11. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Provider Terraform API gaps | Some modules can't fully remediate | Stub with limitations, document workarounds |
| Remediation engine complexity | Tight coupling between API and Terraform Cloud | Use event-driven architecture, keep engine stateless |
| Module explosion (128 modules) | Maintenance burden, consistency drift | Shared submodules, CI enforcement, module templates |
| Breaking existing module users | Migration path from old paths | Symlinks during transition, deprecation warnings |
| demo_seed.py impact | New modules need test coverage in seed | Phase 1 adds evidence endpoint; seed extended per phase |
| `/api/v1/evidence` is new API surface | Security, validation, abuse potential | ABAC enforcement, rate limiting, input validation |

## 12. Out of Scope

- Frontend UI for remediation management (existing UI covers workflow)
- Terraform Cloud account provisioning (users bring their own)
- Non-Terraform IaC (CloudFormation, ARM, Pulumi) — future consideration
- Connector changes (connectors already emit the findings we need)
- Adding new cloud connectors (e.g., Tencent) — separate effort
- Spot.io (Spotio) connector: FinOps/cost optimization, no IaC remediation surface — findings are advisory only
