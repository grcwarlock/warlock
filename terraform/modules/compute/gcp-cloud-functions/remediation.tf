locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["SC-7", "SC-28", "AU-2"]
    connectors    = ["gcp"]
    limitations   = []
  }
}
