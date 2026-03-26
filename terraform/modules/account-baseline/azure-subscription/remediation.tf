locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["AU-2", "AU-6", "SC-28"]
    connectors    = ["azure"]
    limitations   = []
  }
}
