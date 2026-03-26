###############################################################################
# Warlock Standard Tags/Labels — Shared Submodule
# Produces a merged tag map with Warlock standard fields.
# Usage: module "tags" { source = "../../_shared/tags" ... }
###############################################################################

locals {
  standard = {
    ManagedBy     = "warlock"
    Module        = var.module_name
    Framework     = "NIST-800-53"
    RemediationId = var.remediation_id != null ? var.remediation_id : "none"
  }
}
