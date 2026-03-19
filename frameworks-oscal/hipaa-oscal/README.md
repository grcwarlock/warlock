# HIPAA Security Rule

OSCAL-aligned compliance package for the HIPAA Security Rule (45 CFR Part 164).

## What's in This Package

```
hipaa-oscal/
  catalog/catalog.json    # OSCAL catalog of HIPAA Security Rule controls
  profiles/               # Baseline profiles
  policies/               # OPA/Rego policies for automated control checks
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate HIPAA policies against your infrastructure data:

```bash
opa eval -d frameworks/hipaa-oscal/policies/ -i input.json "data.hipaa"
```

Controls reference 45 CFR 164 sections (e.g., 164.312(a)(1) for Access Control, 164.312(b) for Audit Controls).

## Source / Authority

- **Title:** HIPAA Security Rule (45 CFR Part 164)
- **Version:** 2013
- **OSCAL version:** 1.1.2
- **Authority:** U.S. Department of Health and Human Services (HHS)
- **Reference:** https://www.hhs.gov/hipaa/
- **Framework key:** `hipaa`

## UCF Mapping

Maps to UCF domains via sections like 164.312(a)(1) (Access Control -> UCF-01), 164.312(b) (Audit -> UCF-02), 164.310(d)(1) (Configuration -> UCF-03), and others. Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
