locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["AU-2"]
    connectors    = ["ovh"]
    limitations = [
      "OVH Logs Data Platform has limited Terraform support. Log forwarding must be configured via the OVH Control Panel or API directly.",
    ]
  }
}
