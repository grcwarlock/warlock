locals {
  warlock_remediation = {
    risk_level    = "high"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-28"]
    connectors    = ["hetzner"]
    limitations = [
      "Hetzner Storage Boxes cannot be managed via Terraform. They must be ordered and configured through the Hetzner Robot panel.",
      "Consider using Hetzner Cloud Volumes (hcloud_volume) for block storage instead.",
    ]
  }
}
