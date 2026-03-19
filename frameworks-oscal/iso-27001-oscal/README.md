# ISO/IEC 27001:2022

OSCAL-aligned compliance package for ISO/IEC 27001:2022 Annex A controls.

## What's in This Package

```
iso-27001-oscal/
  catalog/catalog.json    # OSCAL catalog of Annex A controls
  profiles/               # Baseline profiles
  policies/               # 93 OPA/Rego policies organized by Annex A clause
    a5/                   # Organizational controls (A.5.1 - A.5.37)
    a6/                   # People controls (A.6.1 - A.6.8)
    a7/                   # Physical controls (A.7.1 - A.7.14)
    a8/                   # Technological controls (A.8.1 - A.8.34)
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate ISO 27001 policies against your infrastructure data:

```bash
opa eval -d frameworks/iso-27001-oscal/policies/ -i input.json "data.iso27001"
```

Policies expose `deny_*` rules per control (e.g., `deny_no_access_control_policy` in `a5/a5_15_access_control.rego`).

## Source / Authority

- **Title:** ISO/IEC 27001:2022 Annex A Controls
- **Version:** 2022
- **OSCAL version:** 1.1.2
- **Authority:** International Organization for Standardization (ISO) / International Electrotechnical Commission (IEC)
- **Reference:** https://www.iso.org/standard/27001
- **Framework key:** `iso27001`

## UCF Mapping

Maps to UCF domains via controls like A.5.15 (Access Control -> UCF-01), A.8.15 (Logging -> UCF-02), A.8.9 (Configuration Management -> UCF-03), and others. Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
