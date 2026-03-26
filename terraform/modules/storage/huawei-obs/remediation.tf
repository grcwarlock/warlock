locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["SC-28", "AC-3"]
    connectors    = ["huaweicloud", "huaweicloud_obs"]
    limitations   = []
  }
}
