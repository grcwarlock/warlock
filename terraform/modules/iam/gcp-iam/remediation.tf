locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["AC-2", "AC-6", "IA-2"]
    connectors    = ["gcp"]
    limitations   = []
  }
}
