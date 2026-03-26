locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["SI-4", "AU-6"]
    connectors    = ["ibm"]
    limitations = [
      "Some SCC features require manual console configuration",
    ]
  }
}
