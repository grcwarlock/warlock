locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["AU-2"]
    connectors    = ["hetzner"]
    limitations = [
      "Hetzner Cloud does not provide native audit logging via API or Terraform. Server-level logging requires manual syslog configuration.",
      "Recommend deploying a log collector (Fluentd, Vector) on each server and forwarding to a central logging service.",
    ]
  }
}
