locals {
  warlock_remediation = {
    risk_level    = "medium"
    auto_approve  = false
    rollback_safe = true
    control_ids   = ["SC-12"]
    connectors    = ["scaleway"]
    limitations = [
      "Scaleway does not offer a dedicated KMS service. This module uses Secret Manager for secret storage. User-managed encryption keys for other services are not available.",
    ]
  }
}
