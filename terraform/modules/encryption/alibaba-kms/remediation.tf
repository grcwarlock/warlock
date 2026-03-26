locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["SC-12", "SC-28"]
    connectors    = ["alicloud", "alicloud_kms"]
    limitations   = []
  }
}
