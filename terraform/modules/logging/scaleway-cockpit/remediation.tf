locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["AU-2"]
    connectors    = ["scaleway"]
    limitations   = []
  }
}
