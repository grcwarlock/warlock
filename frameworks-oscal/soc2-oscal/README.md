# SOC 2 Type II Trust Services Criteria

OSCAL-aligned compliance package for SOC 2 Type II Trust Services Criteria (2022).

## What's in This Package

```
soc2-oscal/
  catalog/catalog.json    # OSCAL catalog of Trust Services Criteria
  profiles/               # Baseline profiles
  policies/               # 13 OPA/Rego policies covering all criteria categories
    cc1_control_environment.rego
    cc2_communication_information.rego
    cc3_risk_assessment.rego
    cc4_monitoring_activities.rego
    cc5_control_activities.rego
    cc6_logical_access.rego
    cc7_system_operations.rego
    cc8_change_management.rego
    cc9_risk_mitigation.rego
    a1_availability.rego
    c1_confidentiality.rego
    p1_privacy.rego
    pi1_processing_integrity.rego
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate SOC 2 policies against your infrastructure data:

```bash
opa eval -d frameworks/soc2-oscal/policies/ -i input.json "data.soc2"
```

Policies cover the five Trust Services Categories: Security (CC series), Availability (A1), Confidentiality (C1), Processing Integrity (PI1), and Privacy (P1).

## Source / Authority

- **Title:** SOC 2 Type II Trust Services Criteria
- **Version:** 2022
- **OSCAL version:** 1.1.2
- **Authority:** American Institute of Certified Public Accountants (AICPA)
- **Reference:** https://www.aicpa.org/soc2
- **Framework key:** `soc2`

## UCF Mapping

Maps to UCF domains via criteria like CC6.1-CC6.3 (Access Control -> UCF-01), CC7.2 (Audit -> UCF-02), CC8.1 (Change Management -> UCF-03/UCF-16), and others. Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
