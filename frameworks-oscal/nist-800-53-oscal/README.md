# NIST SP 800-53 Rev 5

OSCAL-aligned compliance package for NIST Special Publication 800-53 Revision 5 security and privacy controls.

## What's in This Package

```
nist-800-53-oscal/
  catalog/catalog.json    # Full OSCAL catalog of 800-53 Rev 5.1 controls
  profiles/               # Baseline profiles (low, moderate, high)
  policies/               # 143 OPA/Rego policies organized by control family
    ac/                   # Access Control (AC-1 through AC-25)
    at/                   # Awareness and Training
    au/                   # Audit and Accountability
    ca/                   # Assessment, Authorization, and Monitoring
    cm/                   # Configuration Management
    cp/                   # Contingency Planning
    ia/                   # Identification and Authentication
    ir/                   # Incident Response
    ma/                   # Maintenance
    mp/                   # Media Protection
    pe/                   # Physical and Environmental Protection
    pl/                   # Planning
    pm/                   # Program Management
    ps/                   # Personnel Security
    pt/                   # Personally Identifiable Information Processing
    ra/                   # Risk Assessment
    sa/                   # System and Services Acquisition
    sc/                   # System and Communications Protection
    si/                   # System and Information Integrity
    sr/                   # Supply Chain Risk Management
  mappings/               # Pairwise mappings to SOC 2, ISO 27001, HIPAA, CMMC L2
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate NIST 800-53 policies against your infrastructure data:

```bash
opa eval -d frameworks/nist-800-53-oscal/policies/ -i input.json "data.nist"
```

Each policy file uses the package namespace `nist.<family>.<control_id>` and exposes `deny_*` rules that return violation messages when controls are not met.

## Source / Authority

- **Title:** NIST SP 800-53 Rev 5 -- Security and Privacy Controls for Information Systems and Organizations
- **Version:** 5.1
- **OSCAL version:** 1.1.2
- **Authority:** National Institute of Standards and Technology (NIST)
- **Reference:** https://github.com/usnistgov/oscal-content
- **Framework key:** `nist_800_53`

## UCF Mapping

This framework maps to UCF domains UCF-01 through UCF-22 via `unified-controls-framework/mappings/framework-mappings.json`. NIST 800-53 provides the most comprehensive control coverage across all UCF domains.

## Enhancement Coverage Gap

This catalog contains 293 base controls. The pipeline's nist_800_53.yaml defines 1,176 controls including all enhancements. Enhancement-level OSCAL entries should be generated from the official NIST OSCAL content for full coverage.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
