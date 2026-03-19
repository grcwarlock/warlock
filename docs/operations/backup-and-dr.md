# Backup and Disaster Recovery

## Production Database Requirements

Warlock MUST run on PostgreSQL in production. SQLite is for development only.

### Managed PostgreSQL (Recommended)

| Provider | Service | Minimum Config |
|----------|---------|----------------|
| AWS | RDS PostgreSQL 16 | Multi-AZ, 35-day backup retention |
| GCP | Cloud SQL | HA, automated backups, PITR enabled |
| Azure | Azure Database for PostgreSQL | Zone-redundant HA |

### Backup Configuration

- **Automated backups:** Enable with 35-day retention (SOC 2 / FedRAMP requirement)
- **Point-in-time recovery (PITR):** Must be enabled — allows recovery to any second
- **Cross-region replication:** Recommended for DR — async replica in secondary region
- **WAL archiving:** Enable for continuous archiving to object storage

### Recovery Targets

| Metric | Target | Justification |
|--------|--------|---------------|
| RPO (Recovery Point Objective) | 1 hour | Maximum acceptable data loss |
| RTO (Recovery Time Objective) | 4 hours | Maximum acceptable downtime |

### Export Artifact Archival

OSCAL exports, audit binders, and compliance reports must be archived:

```bash
# Archive to S3 with versioning
aws s3 sync exports/ s3://warlock-compliance-exports/ --storage-class STANDARD_IA
```

Enable S3 versioning and lifecycle policies:
- Standard IA after 30 days
- Glacier after 365 days
- No deletion (compliance evidence must be retained)

### Data Retention

Warlock's retention scheduler runs weekly and enforces:
- Framework-specific retention periods (HIPAA: 6 years, SOC 2: 7 years, GDPR: varies)
- Legal hold protection — no data deleted while a hold is active
- Audit trail entries for all purge operations

### Disaster Recovery Procedure

1. **Failover:** Promote read replica to primary (RDS: automatic for Multi-AZ)
2. **Verify:** Run `alembic current` to confirm migration state
3. **Health check:** Confirm `/api/v1/health` returns 200
4. **Audit trail:** Run `/api/v1/audit-trail/verify` to confirm chain integrity
5. **Pipeline:** Trigger `POST /api/v1/pipeline/collect` to resume data collection
