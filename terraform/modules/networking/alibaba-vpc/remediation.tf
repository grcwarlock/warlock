locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-7", "AU-2"]
    connectors    = ["alicloud", "alicloud_vpc"]
    limitations   = []
  }
}
