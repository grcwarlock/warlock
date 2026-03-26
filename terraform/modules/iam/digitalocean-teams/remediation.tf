locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["AC-2"]
    connectors    = ["digitalocean"]
    limitations = [
      "DigitalOcean team management is not available via Terraform. Teams must be managed through the dashboard.",
    ]
  }
}
