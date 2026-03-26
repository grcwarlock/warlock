locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["SC-7"]
    connectors    = ["hetzner"]
    limitations   = []
  }
}
