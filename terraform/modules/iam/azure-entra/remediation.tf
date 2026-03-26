locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["AC-2", "IA-2", "AC-6"]
    connectors    = ["azure"]
    limitations   = []
  }
}
