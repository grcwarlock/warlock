locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["AU-2", "AC-3", "SC-28"]
    connectors    = ["oci"]
    limitations   = []
  }
}
