locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-7"]
    connectors    = ["huaweicloud", "huaweicloud_vpc"]
    limitations   = []
  }
}
