# Warlock OSCAL Framework Packages

OSCAL-aligned compliance packages for the Warlock GRC pipeline.

## Package Status

### With Pipeline YAML and OSCAL Catalog

These frameworks have both a pipeline YAML definition (`warlock/frameworks/`) and an OSCAL catalog package:

| Framework | Pipeline YAML | OSCAL Package |
|-----------|--------------|---------------|
| NIST 800-53 Rev 5 | `warlock/frameworks/nist_800_53.yaml` | `nist-800-53-oscal/` |
| ISO 27001:2022 | `warlock/frameworks/iso_27001.yaml` | `iso-27001-oscal/` |
| ISO 42001:2023 | `warlock/frameworks/iso_42001.yaml` | `iso-42001-oscal/` |
| SOC 2 (TSC) | `warlock/frameworks/soc2.yaml` | `soc2-oscal/` |
| UCF | `warlock/frameworks/ucf.yaml` | `unified-controls-framework/` |

### OSCAL-Only (No Pipeline YAML)

These frameworks have OSCAL catalog packages but no pipeline YAML definition yet. They can be used for OSCAL document generation and cross-framework mapping but do not yet have automated evidence collection or assertion evaluation:

- `cmmc-oscal/` -- CMMC Level 2
- `fedramp-oscal/` -- FedRAMP
- `gdpr-oscal/` -- GDPR
- `hipaa-oscal/` -- HIPAA
- `pci-dss-oscal/` -- PCI DSS 4.0

### Pipeline-Only (No OSCAL Catalog)

These frameworks have pipeline YAML definitions but no OSCAL catalog package yet:

- `warlock/frameworks/iso_27701.yaml` -- ISO 27701:2019 (PIMS)

## Structure

Each OSCAL package follows a consistent layout:

```
<framework>-oscal/
  catalog/catalog.json    # OSCAL 1.1.2 catalog
  profiles/               # Baseline profiles (where applicable)
  mappings/               # Cross-framework mappings
  tests/                  # Validation tests
```

## OSCAL Version

All catalogs conform to OSCAL version 1.1.2.
