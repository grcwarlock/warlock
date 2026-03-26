locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["SC-28", "CM-6"]
    connectors    = ["gcp"]
    limitations   = []
  }
}
