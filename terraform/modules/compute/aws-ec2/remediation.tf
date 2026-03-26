locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["SC-28", "CM-6", "AC-3"]
    connectors    = ["aws"]
    limitations   = []
  }
}
