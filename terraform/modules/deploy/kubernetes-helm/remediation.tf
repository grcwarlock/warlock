locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-7", "SC-28", "AU-2"]
    connectors    = ["kubernetes"]
    limitations   = []
  }
}
