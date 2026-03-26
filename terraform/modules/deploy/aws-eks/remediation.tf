locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["SC-7", "SC-28", "AC-3"]
    connectors    = ["aws"]
    limitations   = []
  }
}
