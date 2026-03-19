# CMMC Level 2

OSCAL-aligned compliance package for the Cybersecurity Maturity Model Certification (CMMC) Level 2, based on NIST SP 800-171 Rev 2.

## What's in This Package

```
cmmc-oscal/
  catalog/catalog.json    # OSCAL catalog of CMMC L2 practices
  profiles/               # Baseline profiles
  policies/               # OPA/Rego policies for automated control checks
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate CMMC policies against your infrastructure data:

```bash
opa eval -d frameworks/cmmc-oscal/policies/ -i input.json "data.cmmc"
```

Controls use the CMMC L2 practice naming convention (e.g., AC.L2-3.1.1, AU.L2-3.3.1).

## Source / Authority

- **Title:** CMMC Level 2 (NIST SP 800-171 Rev 2)
- **Version:** 1.0
- **OSCAL version:** 1.1.2
- **Authority:** U.S. Department of Defense (DoD) Chief Information Officer
- **Reference:** https://dodcio.defense.gov/cmmc/
- **Framework key:** `cmmc_l2`

## UCF Mapping

Maps to UCF domains via practices like AC.L2-3.1.1 (Access Control -> UCF-01), AU.L2-3.3.1 (Audit -> UCF-02), CM.L2-3.4.1 (Configuration -> UCF-03), and others. Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
