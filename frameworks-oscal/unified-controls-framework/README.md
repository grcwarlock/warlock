# Unified Controls Framework (UCF)

The UCF is a superset control taxonomy that maps controls across all supported compliance frameworks through a shared set of domain IDs, eliminating the need for pairwise (N-squared) mappings.

## What's in This Package

```
unified-controls-framework/
  catalog/ucf-catalog.json              # 22 UCF domains (UCF-01 through UCF-22)
  mappings/framework-mappings.json      # Maps each framework's controls to UCF domains
  generated/crosswalk-matrix.json       # Auto-generated pairwise crosswalk matrix
  scripts/generate_crosswalks.py        # Script to regenerate the crosswalk matrix
  tests/                                # Validation tests
```

## UCF Domains

The catalog defines 22 domains spanning security, operations, governance, privacy, and physical categories:

| ID | Domain | Category |
|----|--------|----------|
| UCF-01 | Access Control | security |
| UCF-02 | Audit & Accountability | security |
| UCF-03 | Configuration Management | operations |
| UCF-04 | Identification & Authentication | security |
| UCF-05 | Incident Response | operations |
| UCF-06 | System & Communications Protection | security |
| UCF-07 | System & Information Integrity | security |
| UCF-08 | Risk Assessment | governance |
| UCF-09 | Personnel Security | governance |
| UCF-10 | Physical Protection | physical |
| UCF-11 | Awareness & Training | governance |
| UCF-12 | Contingency Planning | operations |
| UCF-13 | Cryptography & Key Management | security |
| UCF-14 | Data Protection & Privacy | privacy |
| UCF-15 | Vulnerability Management | security |
| UCF-16 | Change Management | operations |
| UCF-17 | Logging & Monitoring | security |
| UCF-18 | Supply Chain Risk Management | governance |
| UCF-19 | Media Protection | physical |
| UCF-20 | Maintenance | operations |
| UCF-21 | Network Access Control | security |
| UCF-22 | Secure Development | operations |

## How It Works

Each framework maps its controls to UCF domain IDs once. Crosswalks between any two frameworks are derived by finding controls that share a UCF domain.

```
Framework A control  -->  UCF Domain  <--  Framework B control
     AC-2            -->   UCF-01    <--   CC6.1, CC6.2
     AU-2            -->   UCF-02    <--   CC7.2
```

This means adding a 9th framework requires only one new set of mappings (to UCF domains), not 8 pairwise mapping files.

## Supported Frameworks

| Key | Framework | Package |
|-----|-----------|---------|
| `nist_800_53` | NIST 800-53 | `nist-800-53-oscal/` |
| `soc2` | SOC 2 | `soc2-oscal/` |
| `iso27001` | ISO 27001 | `iso-27001-oscal/` |
| `hipaa` | HIPAA | `hipaa-oscal/` |
| `cmmc_l2` | CMMC L2 | `cmmc-oscal/` |
| `fedramp_moderate` | FedRAMP Moderate | `fedramp-oscal/` |
| `gdpr` | GDPR | `gdpr-oscal/` |
| `iso_42001` | ISO 42001 | `iso-42001-oscal/` |

## Usage

**Regenerate the crosswalk matrix** after modifying mappings:

```bash
python frameworks/unified-controls-framework/scripts/generate_crosswalks.py
```

**Look up a crosswalk** programmatically by reading `generated/crosswalk-matrix.json`. Each entry in `crosswalks` is keyed as `<source>_to_<target>` and contains an array of mapped control pairs with their shared UCF domain.

## Adding a New Framework to the UCF

1. Add a new entry to `supported-frameworks` in `mappings/framework-mappings.json`.
2. For each domain in `domain-mappings`, add the new framework's relevant controls to the `controls` object.
3. Run `scripts/generate_crosswalks.py` to regenerate the crosswalk matrix.

## Standalone Use

This package is designed to be split into its own repository. It depends only on the framework-mappings data and can generate crosswalks independently of the warlock application.
