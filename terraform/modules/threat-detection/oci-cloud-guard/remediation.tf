locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["SI-4", "AU-6"]
    connectors    = ["oci"]
    limitations   = []
  }
}
