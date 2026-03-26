locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["AU-2", "AC-6", "SC-28"]
    connectors    = ["aws_govcloud"]
    limitations   = ["GovCloud regions have limited service availability. Some Security Hub standards may not be available."]
  }
}
