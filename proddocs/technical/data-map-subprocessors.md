# Data map and subprocessors (DDQ / DPA)

This document supports **due diligence questionnaires** and **data processing addenda**. It describes categories of data processed by Warlock and typical subprocessors when you deploy the platform. **Your** subprocessors depend on **your** hosting choices (cloud region, managed DB, observability).

## Categories of data

| Category | Where it lives | Notes |
|----------|----------------|-------|
| **Identity & access** | PostgreSQL (`users`, API keys, sessions) | Email, name, role, SSO subject id, optional MFA secrets (stored per model design). |
| **GRC telemetry** | PostgreSQL | Findings, controls, evidence metadata, audit trail entries, connector runs — may include resource identifiers and scrubbed text per normalizer PII rules. |
| **Audit & compliance artifacts** | PostgreSQL; optional lake paths | Hash-chained audit sequence; optional Parquet/DuckDB lake for analytics. |
| **AI-assisted content** | Transient to LLM provider when enabled | Prompts should use sanitized evidence (`WLK_AI_*`). No long-term storage of prompts at Warlock unless you add logging — configure `WLK_AI_*` and provider policies. |
| **Logs** | Stdout / log aggregator (your choice) | Correlation IDs; avoid logging raw secrets. |
| **Exports** | Filesystem or object store per `WLK_LAKE_*` / export paths | PDF, Excel, OSCAL packages — customer-controlled retention. |

## Typical subprocessors (configure vs actual)

| Function | Example subprocessor | Controlled by |
|----------|----------------------|-----------------|
| **Hosting / VM / K8s** | AWS, Azure, GCP | Customer deployment |
| **Managed PostgreSQL** | RDS, Cloud SQL, Aurora | Customer deployment |
| **Redis** | ElastiCache, Memorystore for `WLK_CACHE_URL` | Customer deployment |
| **LLM inference** | Anthropic, OpenAI, Google, Ollama Cloud per `WLK_AI_PROVIDER` | Config + API keys |
| **Error tracking** | Sentry if `WLK_SENTRY_DSN` set | Config |
| **Email** | SMTP provider per `WLK_SMTP_*` | Config |

**Warlock does not** require a separate “data lake vendor” such as Snowflake for core operation; optional **enterprise warehouses** are fed by **your** export/ETL processes.

## GDPR / retention

- **Erasure**: Product design uses anonymization patterns for GDPR (see `warlock/workflows/gdpr.py` and project rules).  
- **Retention**: Configure pipeline and retention settings per environment; backups are **customer infrastructure**.

---

*Legal ownership of representations rests with your counsel; engineering maintains technical accuracy of config flags and storage locations.*
