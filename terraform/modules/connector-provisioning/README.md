# Connector Provisioning Terraform Modules

Terraform modules for provisioning the infrastructure prerequisites that Warlock GRC connectors need to collect security evidence from target environments.

These modules complement the existing **drift-detection** modules. Where drift-detection reads Terraform state to find configuration drift, connector-provisioning creates the IAM roles, secrets, network rules, and credentials that connectors use to pull findings.

## Modules

### `aws/`

Provisions AWS connector prerequisites for cross-account security evidence collection.

| Resource | Purpose |
|---|---|
| IAM Role | Cross-account assume role with SecurityAudit + ReadOnlyAccess |
| Region restriction policy | Optional deny policy limiting access to allowed regions |
| KMS Key | Encrypts connector credentials stored in SSM |
| SSM Parameters | SecureString storage for connector API keys |
| CloudWatch Log Group | Audit log destination for connector activity |

**Variables:** `warlock_account_id`, `external_id`, `allowed_regions`, `connector_api_keys`
**Outputs:** `role_arn`, `kms_key_arn`, `ssm_parameter_arns`
**Controls:** AC-2, AC-3, SC-12, AU-3

```hcl
module "aws_connector" {
  source = "./modules/connector-provisioning/aws"

  warlock_account_id = "123456789012"
  external_id        = "warlock-prod-abc123"
  allowed_regions    = ["us-east-1", "us-west-2"]
}
```

### `azure/`

Provisions Azure connector prerequisites via service principal and Key Vault.

| Resource | Purpose |
|---|---|
| Azure AD Application + SP | Service principal with Reader + Security Reader roles |
| Key Vault | Credential storage with access policies |
| Diagnostic Settings | Key Vault audit log export to Log Analytics |

**Variables:** `subscription_id`, `warlock_app_id`, `location`, `log_analytics_workspace_id`
**Outputs:** `client_id`, `tenant_id`, `key_vault_name`
**Controls:** AC-2, AC-3, SC-12, AU-3

```hcl
module "azure_connector" {
  source = "./modules/connector-provisioning/azure"

  subscription_id            = "12345678-1234-1234-1234-123456789012"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}
```

### `gcp/`

Provisions GCP connector prerequisites with workload identity federation for keyless auth.

| Resource | Purpose |
|---|---|
| Service Account | Security Reviewer + SCC Findings Viewer roles |
| Workload Identity Pool | Keyless authentication from AWS or OIDC providers |
| Secret Manager Secrets | API token storage per connector |

**Variables:** `project_id`, `warlock_pool_id`, `warlock_aws_account_id`, `warlock_oidc_issuer`
**Outputs:** `service_account_email`, `workload_identity_pool`, `secret_ids`
**Controls:** AC-2, AC-3, SC-12, IA-2

```hcl
module "gcp_connector" {
  source = "./modules/connector-provisioning/gcp"

  project_id             = "my-gcp-project"
  warlock_aws_account_id = "123456789012"
}
```

### `saas/`

Generic SaaS connector credential management with pluggable secret backends.

| Backend | Storage | Rotation |
|---|---|---|
| `vault` | HashiCorp Vault KV v2 | Via Vault lease/TTL |
| `aws_sm` | AWS Secrets Manager | Via rotation Lambda |
| `env` | Environment variables | Manual |

**Variables:** `connector_name`, `secret_backend`, `rotation_days`, `secret_data`
**Outputs:** `secret_path`, `vault_policy_name`, `aws_secret_arn`
**Controls:** SC-12, SC-28, IA-5

```hcl
module "github_connector" {
  source = "./modules/connector-provisioning/saas"

  connector_name = "github"
  secret_backend = "aws_sm"
  rotation_days  = 90
  secret_data = {
    api_token = var.github_token
  }
}
```

### `ot-ics/`

OT/ICS network prerequisites for industrial security connectors (Claroty, Dragos, Nozomi).

| Resource | Purpose |
|---|---|
| Security Groups | Egress from Warlock to OT; ingress from Warlock on OT side |
| Network ACL | Defense-in-depth boundary enforcement (optional) |
| VPC Flow Logs | Audit trail for all OT boundary traffic |

**Variables:** `vendor` (claroty/dragos/nozomi), `ot_network_cidr`, `warlock_network_cidr`, `vpc_id`
**Outputs:** `firewall_rule_ids`, `flow_log_group_name`
**Controls:** SC-7, AC-4, CA-3

```hcl
module "dragos_connector" {
  source = "./modules/connector-provisioning/ot-ics"

  vendor               = "dragos"
  ot_network_cidr      = "10.100.0.0/16"
  warlock_network_cidr = "10.0.0.0/16"
  vpc_id               = "vpc-abc123"
}
```

### `physical-security/`

Physical security connector setup for access control panels (Lenel, Genetec, HID).

| Resource | Purpose |
|---|---|
| Security Group | Network access from Warlock to panel endpoint |
| Secrets Manager / SSM | API credential storage |
| SSM Parameter | Panel endpoint configuration |
| CloudWatch Log Group | Physical security audit trail |

**Variables:** `vendor` (lenel/genetec/hid), `panel_endpoint`, `secret_backend`, `vpc_id`
**Outputs:** `api_endpoint`, `secret_path`, `security_group_id`
**Controls:** PE-3, PE-6, SC-12

```hcl
module "lenel_connector" {
  source = "./modules/connector-provisioning/physical-security"

  vendor         = "lenel"
  panel_endpoint = "10.50.1.100"
  secret_backend = "aws_sm"
  vpc_id         = "vpc-abc123"
}
```

## Common Features

All modules share these patterns:

- **Self-registration**: Each module calls the `_shared/warlock-registration` submodule to post evidence to the Warlock API when applied (set `warlock_api_endpoint` and `warlock_api_token`)
- **Tagging**: All resources tagged with `managed_by = "warlock"` and `component = "connector-provisioning"`
- **Input validation**: Variables include validation blocks with clear error messages
- **Least privilege**: IAM roles and policies follow the principle of least privilege with read-only access
- **Encryption**: Credentials encrypted at rest via KMS, Key Vault, or Secret Manager

## Requirements

| Name | Version |
|---|---|
| Terraform | >= 1.5, < 2.0 |
| AWS provider | ~> 5.0 |
| Azure provider | ~> 3.0 |
| AzureAD provider | ~> 2.0 |
| Google provider | ~> 5.0 |
| Vault provider | ~> 4.0 |
