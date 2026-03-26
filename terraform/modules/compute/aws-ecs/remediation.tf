locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["AC-3", "SC-7", "AU-2"]
    connectors    = ["aws"]
    limitations   = []
  }
}
