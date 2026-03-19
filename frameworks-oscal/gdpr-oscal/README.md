# EU General Data Protection Regulation (GDPR)

OSCAL-aligned compliance package for the European Union General Data Protection Regulation (Regulation 2016/679).

## What's in This Package

```
gdpr-oscal/
  catalog/catalog.json    # OSCAL catalog of GDPR articles as controls
  profiles/               # Baseline profiles
  policies/               # OPA/Rego policies for automated control checks
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate GDPR policies against your infrastructure data:

```bash
opa eval -d frameworks/gdpr-oscal/policies/ -i input.json "data.gdpr"
```

Controls reference GDPR articles (e.g., Art5-1f for data security principles, Art32-1 for security of processing, Art30-1 for records of processing activities).

## Source / Authority

- **Title:** EU General Data Protection Regulation (2016/679)
- **Version:** 2016/679
- **OSCAL version:** 1.1.2
- **Authority:** European Parliament and Council of the European Union
- **Reference:** https://gdpr.eu/
- **Framework key:** `gdpr`

## UCF Mapping

Maps to UCF domains via articles like Art5-1f, Art32-1 (Access Control -> UCF-01), Art30-1 (Audit -> UCF-02), and others. GDPR is principles-based, so not all UCF domains have GDPR mappings (e.g., Configuration Management and some operational domains have no direct GDPR equivalent). Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
