locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = true
    control_ids   = ["SI-4"]
    connectors    = ["huaweicloud", "huaweicloud_hss"]
    limitations = [
      "HSS edition activation (Basic/Enterprise/Premium) must be performed via the Huawei Cloud console.",
      "Vulnerability scanning policies, baseline check schedules, and intrusion detection rules require console configuration.",
      "The huaweicloud_hss_host_group resource may not be available in all provider versions; verify provider ~> 1.60 support.",
    ]
  }
}
