locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["AU-2", "AC-6", "SC-28"]
    connectors    = ["huaweicloud", "huaweicloud_cts", "huaweicloud_iam", "huaweicloud_obs"]
    limitations   = []
  }
}
