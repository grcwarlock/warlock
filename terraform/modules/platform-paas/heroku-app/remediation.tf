locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-7", "CM-6"]
    connectors    = ["heroku"]
    limitations   = ["Heroku Terraform provider does not support all platform features. Container deployment requires Heroku CLI."]
  }
}
