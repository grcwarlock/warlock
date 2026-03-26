locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["AU-2", "AC-3", "SC-28"]
    connectors    = ["gcp"]
    limitations   = []
  }
}
