locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-7"]
    connectors    = ["kubernetes"]
    limitations   = []
  }
}
