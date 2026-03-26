locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["CM-3", "CM-8"]
    connectors    = ["gcp"]
    limitations   = []
  }
}
