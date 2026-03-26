locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["SC-28"]
    connectors    = ["digitalocean"]
    limitations = [
      "DigitalOcean Spaces encrypts at rest by default. No user-managed encryption keys available.",
    ]
  }
}
