locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["AU-6", "SI-4"]
    connectors    = ["aws"]
    limitations   = []
  }
}
