locals {
  warlock_remediation = {
    risk_level    = "low"
    auto_approve  = true
    rollback_safe = false
    control_ids   = ["SC-12", "IA-5"]
    connectors    = ["azure", "azure_keyvault"]
    limitations   = []
  }
}
