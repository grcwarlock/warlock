# Data residency and deployment

## Single-region (typical)

- **Application**: Warlock API and workers run in **your** chosen region (e.g. one AWS/Azure/GCP region).
- **PostgreSQL**: Primary database URL via `WLK_DATABASE_URL` — place in the **same jurisdiction** as your compliance requirement.
- **Read replica**: Optional `WLK_DATABASE_READ_URL` for read-heavy paths; document replication lag for your threat model.

## Encryption

- **In transit**: TLS between clients and API; TLS to PostgreSQL and Redis when supported by drivers and platform.
- **At rest**: Use **platform-managed encryption** for DB disks and backups (RDS, Azure Disk, etc.). Field-level encryption uses `WLK_ENCRYPTION_KEY` where enabled in code paths.

## Multi-tenancy and geography

- **Logical tenant isolation**: When `WLK_MULTI_TENANCY_ENABLED=true`, rows are scoped by `tenant_id`. This is **logical** isolation in one database — not automatic **geo-partitioning**.
- **Geo-pinned tenants** (multi-region SaaS): Not automatic. Options on a roadmap:
  - **Separate deployments** per region (strong isolation).
  - **Per-region databases** with routing at the edge (larger engineering).
- **Self-hosted / VPC**: Customer deploys entirely inside their account — residency follows **their** cloud.

## Data lake paths

- **In-app lake** (`warlock/lake/`): DuckDB/Parquet paths are **on your filesystem or object prefix** configured by `WLK_LAKE_*` — residency follows **that** storage location.

---

*Align this document with your actual `WLK_*` values and infrastructure diagrams for procurement.*
