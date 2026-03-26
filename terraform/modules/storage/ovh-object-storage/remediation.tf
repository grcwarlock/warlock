locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = false
    control_ids   = ["SC-28", "AC-3"]
    connectors    = ["ovh"]
    limitations = [
      "OVH Object Storage uses OpenStack Swift. User-managed encryption keys are not available via Terraform.",
    ]
  }
}
