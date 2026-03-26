locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["AC-2", "AC-6"]
    connectors    = ["huaweicloud", "huaweicloud_iam"]
    limitations   = []
  }
}
