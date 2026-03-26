locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["CM-6", "SI-3"]
    connectors    = ["kubernetes"]
    limitations   = []
  }
}
