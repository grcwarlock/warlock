locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["SI-4", "AU-6"]
    connectors    = ["alicloud", "alicloud_security_center"]
    limitations = [
      "Security Center edition (Basic/Anti-virus/Advanced/Enterprise) must be activated via the Alibaba Cloud console — Terraform manages asset grouping only.",
      "Threat detection policies and vulnerability scanning schedules require console configuration.",
    ]
  }
}
