# Terraform Module Expansion — Phase 1: Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared infrastructure (submodules, remediation engine, container image, directory structure) and migrate all 12 existing modules to the new domain-first layout.

**Architecture:** Domain-first module organization under `terraform/modules/<domain>/<provider>-<service>/`. Shared submodules in `_shared/` handle Warlock API registration and remediation triggers. Existing modules move unchanged (except updated self-registration to use shared submodule and updated module paths in evidence POSTs). Container image enables cloud-native deployment.

**Tech Stack:** Terraform >= 1.5, AWS/Azure/GCP providers, Docker, docker-compose, Python 3.12 (API endpoint)

**Spec:** `docs/superpowers/specs/2026-03-26-terraform-module-expansion-design.md`

---

### Task 1: Create _shared/warlock-registration submodule

**Files:**
- Create: `terraform/modules/_shared/warlock-registration/main.tf`
- Create: `terraform/modules/_shared/warlock-registration/variables.tf`
- Create: `terraform/modules/_shared/warlock-registration/outputs.tf`

- [ ] **Step 1: Create warlock-registration main.tf**

```hcl
# terraform/modules/_shared/warlock-registration/main.tf
###############################################################################
# Warlock Self-Registration — Shared Submodule
# Posts evidence to the Warlock API when a module is applied.
# Include in every domain module via: module "warlock_registration" { ... }
###############################################################################

resource "terraform_data" "warlock_evidence" {
  count = var.enabled ? 1 : 0

  triggers_replace = [var.resource_id]

  provisioner "local-exec" {
    environment = {
      WARLOCK_API_ENDPOINT = var.api_endpoint
      WARLOCK_API_TOKEN    = var.api_token
    }
    command = <<-EOT
      curl -sf -X POST "$WARLOCK_API_ENDPOINT/api/v1/evidence" \
        -H "Authorization: Bearer $WARLOCK_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '${jsonencode({
          module         = var.module_name
          resource_id    = var.resource_id
          control_ids    = var.control_ids
          attributes     = var.attributes
          action         = var.remediation_id != null ? "remediate" : "provision"
          remediation_id = var.remediation_id
        })}' || true
    EOT
  }
}
```

- [ ] **Step 2: Create warlock-registration variables.tf**

```hcl
# terraform/modules/_shared/warlock-registration/variables.tf

variable "enabled" {
  description = "Whether to POST evidence to the Warlock API"
  type        = bool
  default     = false
}

variable "api_endpoint" {
  description = "Warlock API base URL (e.g. https://warlock.example.com)"
  type        = string
  default     = ""
}

variable "api_token" {
  description = "Bearer token for Warlock API authentication"
  type        = string
  default     = ""
  sensitive   = true
}

variable "module_name" {
  description = "Domain-qualified module name (e.g. encryption/aws-kms)"
  type        = string
}

variable "resource_id" {
  description = "Cloud resource ID (ARN, Azure resource ID, GCP resource name)"
  type        = string
}

variable "control_ids" {
  description = "NIST 800-53 control IDs this module enforces (e.g. [\"SC-12\", \"SC-28\"])"
  type        = list(string)
}

variable "attributes" {
  description = "Key compliance attributes to report as evidence"
  type        = map(string)
  default     = {}
}

variable "remediation_id" {
  description = "Warlock remediation ID when triggered by closed-loop engine. Null = standalone provision."
  type        = string
  default     = null
}
```

- [ ] **Step 3: Create warlock-registration outputs.tf**

```hcl
# terraform/modules/_shared/warlock-registration/outputs.tf

output "evidence_registered" {
  description = "Whether evidence was posted to the Warlock API"
  value       = var.enabled
}
```

- [ ] **Step 4: Validate the submodule**

Run: `cd /Users/jsn/warlock && terraform -chdir=terraform/modules/_shared/warlock-registration init -backend=false && terraform -chdir=terraform/modules/_shared/warlock-registration validate`
Expected: "Success! The configuration is valid."

- [ ] **Step 5: Commit**

```bash
git add terraform/modules/_shared/warlock-registration/
git commit -m "feat(terraform): add _shared/warlock-registration submodule"
```

---

### Task 2: Create _shared/tags submodule

**Files:**
- Create: `terraform/modules/_shared/tags/main.tf`
- Create: `terraform/modules/_shared/tags/variables.tf`
- Create: `terraform/modules/_shared/tags/outputs.tf`

- [ ] **Step 1: Create tags main.tf**

```hcl
# terraform/modules/_shared/tags/main.tf
###############################################################################
# Warlock Standard Tags/Labels — Shared Submodule
# Produces a merged tag map with Warlock standard fields.
# Usage: module "tags" { source = "../../_shared/tags" ... }
###############################################################################

locals {
  standard = {
    ManagedBy     = "warlock"
    Module        = var.module_name
    Framework     = "NIST-800-53"
    RemediationId = var.remediation_id != null ? var.remediation_id : "none"
  }
}
```

- [ ] **Step 2: Create tags variables.tf**

```hcl
# terraform/modules/_shared/tags/variables.tf

variable "extra_tags" {
  description = "User-supplied tags/labels to merge with Warlock standard tags"
  type        = map(string)
  default     = {}
}

variable "module_name" {
  description = "Domain-qualified module name (e.g. encryption/aws-kms)"
  type        = string
}

variable "remediation_id" {
  description = "Warlock remediation ID (null = standalone)"
  type        = string
  default     = null
}
```

- [ ] **Step 3: Create tags outputs.tf**

```hcl
# terraform/modules/_shared/tags/outputs.tf

output "merged" {
  description = "Merged tag map: Warlock standard + user-supplied tags"
  value       = merge(local.standard, var.extra_tags)
}

output "merged_labels" {
  description = "Same as merged but with lowercase keys and underscores (for GCP/Alibaba labels)"
  value = {
    for k, v in merge(local.standard, var.extra_tags) :
    lower(replace(k, "/[^a-z0-9_-]/", "_")) => lower(v)
  }
}
```

- [ ] **Step 4: Validate**

Run: `terraform -chdir=terraform/modules/_shared/tags init -backend=false && terraform -chdir=terraform/modules/_shared/tags validate`
Expected: "Success! The configuration is valid."

- [ ] **Step 5: Commit**

```bash
git add terraform/modules/_shared/tags/
git commit -m "feat(terraform): add _shared/tags submodule for standard tagging"
```

---

### Task 3: Create domain directory structure and migrate encryption modules

**Files:**
- Create: `terraform/modules/encryption/` directory
- Move: `terraform/modules/aws/kms-baseline/*` → `terraform/modules/encryption/aws-kms/`
- Move: `terraform/modules/azure/key-vault-baseline/*` → `terraform/modules/encryption/azure-keyvault/`
- Move: `terraform/modules/gcp/kms-baseline/*` → `terraform/modules/encryption/gcp-kms/`
- Modify: Each module's warlock_evidence to use `_shared/warlock-registration`
- Modify: Each module's evidence POST module name to new domain path

- [ ] **Step 1: Create encryption directory and copy AWS KMS module**

```bash
mkdir -p terraform/modules/encryption/aws-kms
cp terraform/modules/aws/kms-baseline/* terraform/modules/encryption/aws-kms/
```

- [ ] **Step 2: Update aws-kms to use shared submodule**

In `terraform/modules/encryption/aws-kms/main.tf`:
- Remove the inline `variable "warlock_api_endpoint"`, `variable "warlock_api_token"`, and `resource "terraform_data" "warlock_evidence"` blocks
- Add `warlock_api_endpoint`, `warlock_api_token`, and `warlock_remediation_id` to variables.tf
- Add the shared registration module call
- Update module name in evidence to `encryption/aws-kms`
- Add `remediation.tf` metadata file

- [ ] **Step 3: Update azure-keyvault to use shared submodule**

```bash
mkdir -p terraform/modules/encryption/azure-keyvault
cp terraform/modules/azure/key-vault-baseline/* terraform/modules/encryption/azure-keyvault/
```

Same changes as Step 2 but for Azure: remove inline warlock vars/resource, add shared submodule call, update module name to `encryption/azure-keyvault`.

- [ ] **Step 4: Update gcp-kms to use shared submodule**

```bash
mkdir -p terraform/modules/encryption/gcp-kms
cp terraform/modules/gcp/kms-baseline/* terraform/modules/encryption/gcp-kms/
```

Same changes for GCP: remove inline warlock vars/resource, add shared submodule call, update module name to `encryption/gcp-kms`.

- [ ] **Step 5: Add remediation.tf to each encryption module**

Each gets a `remediation.tf` with appropriate metadata.

- [ ] **Step 6: Validate all three**

```bash
terraform -chdir=terraform/modules/encryption/aws-kms init -backend=false && terraform -chdir=terraform/modules/encryption/aws-kms validate
terraform -chdir=terraform/modules/encryption/azure-keyvault init -backend=false && terraform -chdir=terraform/modules/encryption/azure-keyvault validate
terraform -chdir=terraform/modules/encryption/gcp-kms init -backend=false && terraform -chdir=terraform/modules/encryption/gcp-kms validate
```

- [ ] **Step 7: Commit**

```bash
git add terraform/modules/encryption/
git commit -m "feat(terraform): migrate encryption modules to domain-first layout"
```

---

### Task 4: Migrate remaining 9 modules to domain-first layout

Migrate: logging (cloudtrail-org, config-rules, azure-activity-log, gcp-audit-log), networking (compliant-vpc), iam (iam-baseline), threat-detection (guardduty-org), drift-detection (drift-detector), account-baseline (secure-account-baseline, secure-subscription-baseline, secure-project-baseline).

Note: azure/secure-subscription-baseline splits into logging/azure-activity-log + account-baseline/azure-subscription. gcp/secure-project-baseline splits into logging/gcp-audit-log + account-baseline/gcp-project.

- [ ] Steps follow same pattern as Task 3 for each module.

- [ ] **Commit after each domain is complete.**

---

### Task 5: Create container image (deploy/container-image)

**Files:**
- Create: `terraform/modules/deploy/container-image/Dockerfile`
- Create: `terraform/modules/deploy/container-image/docker-compose.yml`
- Create: `terraform/modules/deploy/container-image/.dockerignore`
- Create: `terraform/modules/deploy/container-image/entrypoint.sh`
- Create: `terraform/modules/deploy/container-image/nginx.conf`

- [ ] **Step 1: Create Dockerfile**

Multi-stage build: Python 3.12-slim, install warlock with all extras, run Gunicorn.

- [ ] **Step 2: Create docker-compose.yml**

Full stack: warlock-api, warlock-worker, postgres:15, redis:7, opa:latest.

- [ ] **Step 3: Create entrypoint.sh**

Run alembic upgrade head, then exec gunicorn.

- [ ] **Step 4: Create nginx.conf**

Reverse proxy with security headers, health check passthrough.

- [ ] **Step 5: Create .dockerignore**

- [ ] **Step 6: Test build**

```bash
cd terraform/modules/deploy/container-image && docker build -t warlock:test .
```

- [ ] **Step 7: Commit**

```bash
git add terraform/modules/deploy/
git commit -m "feat(terraform): add container image for Warlock deployment"
```

---

### Task 6: Remove old module directories

After all modules are migrated and validated, remove the old `aws/`, `azure/`, `gcp/` directories.

- [ ] **Step 1: Verify all old modules are migrated**

```bash
diff <(ls terraform/modules/aws/) <(echo "all migrated")
```

- [ ] **Step 2: Remove old directories**

```bash
rm -rf terraform/modules/aws/ terraform/modules/azure/ terraform/modules/gcp/
```

- [ ] **Step 3: Update CI workflow**

Update `.github/workflows/compliance-gate.yaml` terraform validate paths to use new domain-first paths.

- [ ] **Step 4: Commit**

```bash
git add -A terraform/modules/ .github/workflows/compliance-gate.yaml
git commit -m "refactor(terraform): remove old cloud-first module directories"
```

---

### Task 7: Validate full terraform suite

- [ ] **Step 1: Run terraform validate on every module**

```bash
for dir in terraform/modules/*/; do
  if [ -f "$dir/main.tf" ]; then
    echo "Validating $dir..."
    terraform -chdir="$dir" init -backend=false && terraform -chdir="$dir" validate
  fi
  for subdir in "$dir"*/; do
    if [ -f "$subdir/main.tf" ]; then
      echo "Validating $subdir..."
      terraform -chdir="$subdir" init -backend=false && terraform -chdir="$subdir" validate
    fi
  done
done
```

- [ ] **Step 2: Run terraform fmt check**

```bash
terraform fmt -check -recursive terraform/modules/
```

- [ ] **Step 3: Fix any issues and commit**
