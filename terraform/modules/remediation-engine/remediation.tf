locals {
  warlock_remediation = {
    risk_level    = "critical"
    auto_approve  = false
    rollback_safe = false
    control_ids   = [] # Meta-module: orchestrates other modules
    connectors    = []
    limitations = [
      "Requires Terraform Cloud account and API token",
      "Terraform Cloud workspace auto-creation requires organization-level permissions",
      "Run completion polling has a 240-second timeout",
    ]
  }
}
