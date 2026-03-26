locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["SC-28", "AU-2", "SC-7"]
    connectors    = ["gcp"]
    limitations   = []
  }
}
