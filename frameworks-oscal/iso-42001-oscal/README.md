# ISO/IEC 42001:2023 AI Management System

OSCAL-aligned compliance package for ISO/IEC 42001:2023, the international standard for Artificial Intelligence Management Systems (AIMS).

## What's in This Package

```
iso-42001-oscal/
  catalog/catalog.json    # OSCAL catalog of ISO 42001 Annex A controls
  profiles/               # Baseline profiles
  policies/               # OPA/Rego policies for automated control checks
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate ISO 42001 policies against your infrastructure data:

```bash
opa eval -d frameworks/iso-42001-oscal/policies/ -i input.json "data.iso42001"
```

Controls follow the ISO 42001 Annex A structure covering AI-specific risk management, data governance, transparency, and accountability.

## Source / Authority

- **Title:** ISO/IEC 42001:2023 AI Management System
- **Version:** 2023
- **OSCAL version:** 1.1.2
- **Authority:** International Organization for Standardization (ISO) / International Electrotechnical Commission (IEC)
- **Reference:** https://www.iso.org/standard/81230.html
- **Framework key:** `iso_42001`

## UCF Mapping

Maps to UCF domains via Annex A controls like A5-1 (Access Control -> UCF-01), A9-1 (Audit -> UCF-02), and others. ISO 42001 focuses on AI-specific concerns, so its UCF coverage is narrower than general-purpose frameworks like NIST 800-53. Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
