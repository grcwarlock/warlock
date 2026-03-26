locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["AC-2", "AC-6", "IA-2"]
    connectors    = ["alicloud", "alicloud_ram"]
    limitations   = []
  }
}
