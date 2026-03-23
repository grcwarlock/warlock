# PII Scrubbing at Ingest — Factsheet

## What it does

Warlock now automatically detects and removes personally identifiable information (PII) from all security findings before they reach the database, data lake, or any export. The system answers "was PII present?" without ever storing the PII itself.

## Why it matters

GRC platforms ingest data from 165 source connectors — vulnerability scanners, identity providers, HRIS systems, audit logs, cloud APIs. Many of these sources include personal data: email addresses, employee names, phone numbers. Before this change, that PII flowed through the pipeline and landed in findings, reports, and exports.

Now it doesn't.

## How it works

```
Source API → Connector → Normalizer → PII Scrubber → Database / Lake / Export
                                          │
                                     Scrubs at the
                                     single chokepoint
                                     all 82 normalizers
                                     flow through
```

Every finding passes through the scrubber automatically at the normalizer registry level. No individual connector or normalizer needs PII awareness — the registry handles it.

### Three operations

**1. Raw payload stripping** — Many normalizers historically dumped entire API responses into findings (e.g., the full Okta event object, the full Snyk issue payload). These are removed. Only explicitly extracted, structured fields survive.

**2. Pseudonymization** — Known PII fields (email, display_name, user_name, actor_email, etc.) are replaced with deterministic SHA-256 pseudonyms:

```
jane.smith@company.com  →  person:a1b2c3d4
```

The same input always produces the same pseudonym, so you can correlate across findings ("person:a1b2c3d4 appears in 47 findings across 3 connectors") without knowing the identity.

**3. Pattern scanning** — Free-text fields (titles, descriptions) are scanned for emails, SSNs, and phone numbers using regex detection. Matches are replaced with pseudonyms.

### The compliance flag

Every finding now carries a `pii_detected` boolean. If any PII was found and scrubbed, the flag is `true`. This is the audit artifact — proof that the system detects and handles PII in ingested data.

## Coverage

| Metric | Value |
|--------|-------|
| Connectors covered | All 82 |
| Normalizers covered | All 82 (automatic, via registry) |
| PII types detected | Emails, names, SSNs, phone numbers |
| Known PII field keys monitored | 18 (email, display_name, user_name, actor_email, etc.) |
| Raw payload dump keys stripped | 14 (event, user, issue, response, etc.) |
| Normalizers that previously stored raw payloads | ~25 (38 dump locations) |
| Normalizers that previously stored explicit PII | 29 |

## What this enables

- **Reports are clean by default** — exports, binders, and OSCAL packages contain no PII
- **Data lake is clean** — Parquet files in the lake never contain personal data
- **GDPR compliance** — PII minimization (Article 5(1)(c)) is enforced at the architectural level
- **Auditor confidence** — the `pii_detected` flag provides evidence that the control exists and operates
- **Correlation without exposure** — deterministic pseudonyms allow pattern analysis across findings

## What it does NOT do

- It does not scrub identity tables (Personnel, User) — those intentionally store personal data for access management. The existing GDPR workflows handle data subject rights for those tables.
- It does not scrub raw events (`raw_events` table) — those preserve the original source payload for integrity verification. Access to raw events should be restricted by ABAC.
- It is not a data loss prevention (DLP) system — it targets known PII patterns in structured GRC data, not arbitrary document scanning.

## Architecture

```
warlock/utils/pii.py            — Detection, pseudonymization, scrubbing functions
warlock/normalizers/base.py     — Registry calls scrub_finding() on every finding
warlock/db/models.py            — pii_detected column on Finding model
tests/test_pii.py               — 21 unit tests
```

One new file. Two modified files. One migration. Zero changes to any of the 82 normalizers.
