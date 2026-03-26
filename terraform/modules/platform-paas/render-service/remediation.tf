locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = false
    rollback_safe = true
    control_ids   = []
    connectors    = []
    limitations   = ["Render does not have an official Terraform provider. Services must be configured via the Render Dashboard or API."]
  }
}
