locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["AU-2"]
    connectors    = ["linode"]
    limitations = [
      "Linode has no native log forwarding Terraform resource. Use a syslog agent (rsyslog, Fluentd, Vector) on instances.",
    ]
  }
}
