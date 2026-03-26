locals {
  warlock_remediation = {
    risk_level   = "medium"
    auto_approve = false
    control_ids  = ["CM-3", "CM-8"]
    connectors   = ["aws"]
    limitations = [
      "State-based drift detection requires S3-stored state files",
      "Does not perform live cloud resource comparison — uses state analysis only",
    ]
  }
}
