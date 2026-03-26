locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["SC-7", "SC-28", "AU-2"]
    connectors    = ["azure"]
    limitations   = []
  }
}
