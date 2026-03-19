# FedRAMP Moderate Baseline

OSCAL-aligned compliance package for the Federal Risk and Authorization Management Program (FedRAMP) Moderate Baseline, Rev 5.

## What's in This Package

```
fedramp-oscal/
  catalog/catalog.json    # OSCAL catalog of FedRAMP Moderate controls
  profiles/               # Baseline profiles
  policies/               # OPA/Rego policies for automated control checks
  mappings/               # Pairwise mappings to other frameworks
  tests/                  # Policy and catalog validation tests
```

## Usage

Evaluate FedRAMP policies against your infrastructure data:

```bash
opa eval -d frameworks/fedramp-oscal/policies/ -i input.json "data.fedramp"
```

FedRAMP Moderate builds on NIST 800-53 controls with additional FedRAMP-specific parameters and requirements. Control IDs follow the NIST naming convention (e.g., AC-2, AU-3, SC-7).

## Source / Authority

- **Title:** FedRAMP Moderate Baseline (Rev 5)
- **Version:** Rev 5
- **OSCAL version:** 1.1.2
- **Authority:** General Services Administration (GSA) FedRAMP PMO
- **Reference:** https://www.fedramp.gov/
- **Framework key:** `fedramp_moderate`

## UCF Mapping

Maps to UCF domains via controls like AC-2, AC-3, AC-6 (Access Control -> UCF-01), AU-2, AU-3 (Audit -> UCF-02), CM-2, CM-6 (Configuration -> UCF-03), and others. Control IDs overlap significantly with NIST 800-53 since FedRAMP baselines are derived from it. Full mappings are in `unified-controls-framework/mappings/framework-mappings.json`.

## Standalone Use

This package is designed to be split into its own repository. All paths within the package are relative, and the catalog is self-contained. The only external dependency is the UCF mappings file for cross-framework lookups.
