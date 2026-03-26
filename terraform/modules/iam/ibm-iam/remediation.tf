locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["AC-2", "AC-6"]
    connectors    = ["ibm"]
    limitations   = []
  }
}
