locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["SC-17", "SC-23"]
    connectors    = ["aws", "aws_acm"]
    limitations   = []
  }
}
