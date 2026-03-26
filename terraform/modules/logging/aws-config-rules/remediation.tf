locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["CM-2", "CM-6", "AU-2"]
    connectors    = ["aws"]
    limitations   = []
  }
}
