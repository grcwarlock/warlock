"""Data silo discovery, classification, and protection tracking."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import DataSilo, Finding


class DataSiloManager:
    """Discovers and manages data stores and their sensitive data classification."""

    # Resource types that represent data stores
    STORAGE_RESOURCE_TYPES = {
        "s3_bucket": "s3_bucket",
        "storage_account": "azure_blob",
        "storage_bucket": "gcs_bucket",
        "rds_instance": "rds_database",
        "rds_cluster": "rds_database",
        "dynamodb_table": "dynamodb",
        "redshift_cluster": "redshift",
        "cosmos_db": "cosmos_db",
        "sql_database": "azure_sql",
        "bigquery_dataset": "bigquery",
        "snowflake_database": "snowflake_db",
        "github_repository": "github_repo",
        "sharepoint_site": "sharepoint_site",
        "elasticsearch_domain": "elasticsearch",
    }

    # Provider mapping from source
    PROVIDER_MAP = {
        "aws": "aws",
        "azure": "azure",
        "gcp": "gcp",
        "github": "github",
        "sharepoint": "sharepoint",
        "snowflake": "snowflake",
    }

    def discover_from_findings(self, session: Session) -> dict:
        """Scan Finding table for storage resources and auto-create DataSilo entries.

        Returns {created, updated, total}.
        """
        created = 0
        updated = 0
        now = datetime.now(timezone.utc)

        # Find findings with storage-related resource types
        storage_findings = (
            session.query(Finding)
            .filter(Finding.resource_type.in_(list(self.STORAGE_RESOURCE_TYPES.keys())))
            .all()
        )

        for finding in storage_findings:
            resource_id = finding.resource_id
            if not resource_id:
                continue

            # Check if silo already exists by location (resource_id)
            existing = (
                session.query(DataSilo)
                .filter(DataSilo.location == resource_id)
                .first()
            )

            silo_type = self.STORAGE_RESOURCE_TYPES.get(
                finding.resource_type, finding.resource_type
            )
            provider = self.PROVIDER_MAP.get(finding.source, finding.source)
            detail = finding.detail or {}

            if existing is None:
                silo = DataSilo(
                    name=finding.resource_name or resource_id.split("/")[-1].split(":")[-1],
                    silo_type=silo_type,
                    provider=provider,
                    location=resource_id,
                    data_classification="unknown",
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                )
                session.add(silo)
                created += 1

                # Extract protection info from finding detail
                self._extract_protection_from_detail(silo, detail)
                self._extract_ownership_from_detail(silo, detail, finding)
            else:
                # Update existing silo with latest data
                existing.updated_at = now
                self._extract_protection_from_detail(existing, detail)
                self._extract_ownership_from_detail(existing, detail, finding)
                updated += 1

        session.flush()

        total = session.query(func.count(DataSilo.id)).scalar() or 0
        return {"created": created, "updated": updated, "total": total}

    def _extract_protection_from_detail(self, silo: DataSilo, detail: dict) -> None:
        """Extract encryption and logging status from finding detail."""
        # Encryption at rest
        if "encrypted" in detail or "encryption" in detail:
            enc = detail.get("encrypted", detail.get("encryption", {}))
            if isinstance(enc, bool):
                silo.encrypted_at_rest = enc
            elif isinstance(enc, dict):
                silo.encrypted_at_rest = enc.get("at_rest", enc.get("enabled", False))
                silo.encrypted_in_transit = enc.get("in_transit", None)
            elif isinstance(enc, str):
                silo.encrypted_at_rest = enc.lower() in ("true", "enabled", "aes256", "aws:kms")

        if "server_side_encryption" in detail:
            silo.encrypted_at_rest = bool(detail["server_side_encryption"])

        if "ssl_enforcement" in detail or "require_tls" in detail:
            silo.encrypted_in_transit = bool(
                detail.get("ssl_enforcement", detail.get("require_tls"))
            )

        # Access logging
        if "logging" in detail or "access_logging" in detail:
            log_val = detail.get("logging", detail.get("access_logging"))
            if isinstance(log_val, bool):
                silo.access_logging_enabled = log_val
            elif isinstance(log_val, dict):
                silo.access_logging_enabled = log_val.get("enabled", False)

        # Backup
        if "backup" in detail or "backup_enabled" in detail:
            backup_val = detail.get("backup_enabled", detail.get("backup"))
            if isinstance(backup_val, bool):
                silo.backup_enabled = backup_val
            elif isinstance(backup_val, dict):
                silo.backup_enabled = backup_val.get("enabled", False)

        # Retention
        if "retention_days" in detail:
            try:
                silo.retention_days = int(detail["retention_days"])
            except (ValueError, TypeError):
                pass

    def _extract_ownership_from_detail(
        self, silo: DataSilo, detail: dict, finding: Finding
    ) -> None:
        """Extract ownership from finding detail."""
        silo.owner = detail.get("owner", detail.get("created_by", silo.owner))
        silo.team = detail.get("team", detail.get("department", silo.team))

        # Use account_id from finding if available
        if finding.account_id and not silo.owner:
            silo.owner = f"account:{finding.account_id}"

    def classify_silo(
        self,
        session: Session,
        silo_id: str,
        classification: str,
        contains_pii: bool | None = None,
        contains_phi: bool | None = None,
        contains_pci: bool | None = None,
    ) -> DataSilo:
        """Manually classify a data silo."""
        silo = session.query(DataSilo).filter(DataSilo.id == silo_id).first()
        if not silo:
            raise ValueError(f"Data silo not found: {silo_id}")

        valid_classifications = {"public", "internal", "confidential", "restricted", "unknown"}
        if classification not in valid_classifications:
            raise ValueError(
                f"Invalid classification: {classification}. Must be one of {valid_classifications}"
            )

        silo.data_classification = classification
        if contains_pii is not None:
            silo.contains_pii = contains_pii
        if contains_phi is not None:
            silo.contains_phi = contains_phi
        if contains_pci is not None:
            silo.contains_pci = contains_pci

        # Auto-assign frameworks based on data types
        frameworks: list[str] = list(silo.applicable_frameworks or [])
        if silo.contains_pii and "gdpr" not in frameworks:
            frameworks.append("gdpr")
        if silo.contains_phi and "hipaa" not in frameworks:
            frameworks.append("hipaa")
        if silo.contains_pci and "pci_dss" not in frameworks:
            frameworks.append("pci_dss")
        silo.applicable_frameworks = frameworks

        silo.updated_at = datetime.now(timezone.utc)
        session.flush()
        return silo

    def update_protection_status(self, session: Session, silo_id: str) -> DataSilo:
        """Check related findings for encryption, logging, backup status."""
        silo = session.query(DataSilo).filter(DataSilo.id == silo_id).first()
        if not silo:
            raise ValueError(f"Data silo not found: {silo_id}")

        if not silo.location:
            return silo

        # Find all findings related to this silo's resource
        related_findings = (
            session.query(Finding)
            .filter(Finding.resource_id == silo.location)
            .order_by(Finding.observed_at.desc())
            .all()
        )

        for finding in related_findings:
            detail = finding.detail or {}
            self._extract_protection_from_detail(silo, detail)

            # Check observation type for specific security findings
            if finding.observation_type == "misconfiguration":
                title_lower = finding.title.lower()
                if "encrypt" in title_lower and "not" in title_lower:
                    silo.encrypted_at_rest = False
                elif "logging" in title_lower and ("disabled" in title_lower or "not" in title_lower):
                    silo.access_logging_enabled = False
                elif "backup" in title_lower and ("disabled" in title_lower or "not" in title_lower):
                    silo.backup_enabled = False

        silo.updated_at = datetime.now(timezone.utc)
        session.flush()
        return silo

    def scan_with_purview(self, session: Session, silo_id: str) -> DataSilo:
        """Update scan results from Purview DLP findings for this silo."""
        silo = session.query(DataSilo).filter(DataSilo.id == silo_id).first()
        if not silo:
            raise ValueError(f"Data silo not found: {silo_id}")

        # Look for DLP/Purview/Macie findings related to this silo
        dlp_findings = (
            session.query(Finding)
            .filter(
                Finding.resource_id == silo.location,
                Finding.resource_type.in_([
                    "purview_scan", "macie_finding", "dlp_result",
                    "sensitive_data_discovery",
                ]),
            )
            .order_by(Finding.observed_at.desc())
            .all()
        )

        if not dlp_findings:
            # Also search by name match
            dlp_findings = (
                session.query(Finding)
                .filter(
                    Finding.provider.in_(["purview", "macie", "dlp"]),
                    Finding.resource_name == silo.name,
                )
                .order_by(Finding.observed_at.desc())
                .all()
            )

        scan_findings: list[dict] = []
        sensitive_count = 0
        now = datetime.now(timezone.utc)

        for finding in dlp_findings:
            detail = finding.detail or {}

            # Extract field-level findings
            fields = detail.get("sensitive_fields", detail.get("findings", []))
            if isinstance(fields, list):
                for field in fields:
                    if isinstance(field, dict):
                        scan_findings.append({
                            "field_name": field.get("field_name", field.get("name", "unknown")),
                            "data_type": field.get("data_type", field.get("type", "unknown")),
                            "sample_masked": field.get("sample_masked", "***"),
                            "confidence": field.get("confidence", 0.8),
                        })
                        sensitive_count += 1

            # Update data type flags from DLP findings
            data_types = detail.get("data_types", [])
            if isinstance(data_types, list):
                for dt in data_types:
                    dt_lower = str(dt).lower()
                    if any(term in dt_lower for term in ["pii", "personal", "ssn", "email", "phone"]):
                        silo.contains_pii = True
                    if any(term in dt_lower for term in ["phi", "health", "medical", "hipaa"]):
                        silo.contains_phi = True
                    if any(term in dt_lower for term in ["pci", "credit_card", "card_number", "cvv"]):
                        silo.contains_pci = True
                    if any(term in dt_lower for term in ["credential", "password", "secret", "api_key"]):
                        silo.contains_credentials = True

            if detail.get("total_records"):
                try:
                    silo.total_records = int(detail["total_records"])
                except (ValueError, TypeError):
                    pass

        silo.scan_findings = scan_findings
        silo.sensitive_field_count = sensitive_count
        silo.last_scan_date = now
        silo.scan_status = "completed" if dlp_findings else "not_scanned"
        silo.updated_at = now

        # Auto-classify based on findings
        if silo.data_classification == "unknown":
            if silo.contains_phi or silo.contains_pci:
                silo.data_classification = "restricted"
            elif silo.contains_pii or silo.contains_credentials:
                silo.data_classification = "confidential"
            elif sensitive_count > 0:
                silo.data_classification = "internal"

        # Auto-assign frameworks
        frameworks = list(silo.applicable_frameworks or [])
        if silo.contains_pii and "gdpr" not in frameworks:
            frameworks.append("gdpr")
        if silo.contains_phi and "hipaa" not in frameworks:
            frameworks.append("hipaa")
        if silo.contains_pci and "pci_dss" not in frameworks:
            frameworks.append("pci_dss")
        silo.applicable_frameworks = frameworks

        session.flush()
        return silo

    def unclassified(self, session: Session) -> list[DataSilo]:
        """Return silos still classified as 'unknown'."""
        return (
            session.query(DataSilo)
            .filter(
                DataSilo.data_classification == "unknown",
                DataSilo.is_active == True,  # noqa: E712
            )
            .order_by(DataSilo.created_at.desc())
            .all()
        )

    def unprotected(self, session: Session) -> list[DataSilo]:
        """Return silos lacking encryption or access logging."""
        return (
            session.query(DataSilo)
            .filter(
                DataSilo.is_active == True,  # noqa: E712
                (
                    (DataSilo.encrypted_at_rest == False)  # noqa: E712
                    | (DataSilo.encrypted_at_rest == None)  # noqa: E711
                    | (DataSilo.access_logging_enabled == False)  # noqa: E712
                    | (DataSilo.access_logging_enabled == None)  # noqa: E711
                ),
            )
            .order_by(DataSilo.data_classification.desc(), DataSilo.name)
            .all()
        )

    def pii_silos_without_framework(self, session: Session) -> list[DataSilo]:
        """Return silos containing PII but missing applicable privacy frameworks."""
        all_pii = (
            session.query(DataSilo)
            .filter(
                DataSilo.contains_pii == True,  # noqa: E712
                DataSilo.is_active == True,  # noqa: E712
            )
            .all()
        )

        result = []
        for silo in all_pii:
            frameworks = silo.applicable_frameworks or []
            privacy_frameworks = {"gdpr", "ccpa", "hipaa", "pipeda", "lgpd"}
            if not any(f in privacy_frameworks for f in frameworks):
                result.append(silo)

        return result

    def summary(self, session: Session) -> dict:
        """Stats: total, by type, by classification, pii/phi/pci counts, unprotected count."""
        total = (
            session.query(func.count(DataSilo.id))
            .filter(DataSilo.is_active == True)  # noqa: E712
            .scalar() or 0
        )

        # By type
        type_rows = (
            session.query(DataSilo.silo_type, func.count(DataSilo.id))
            .filter(DataSilo.is_active == True)  # noqa: E712
            .group_by(DataSilo.silo_type)
            .all()
        )
        by_type = {t: c for t, c in type_rows}

        # By classification
        class_rows = (
            session.query(DataSilo.data_classification, func.count(DataSilo.id))
            .filter(DataSilo.is_active == True)  # noqa: E712
            .group_by(DataSilo.data_classification)
            .all()
        )
        by_classification = {cl: c for cl, c in class_rows}

        # By provider
        prov_rows = (
            session.query(DataSilo.provider, func.count(DataSilo.id))
            .filter(DataSilo.is_active == True)  # noqa: E712
            .group_by(DataSilo.provider)
            .all()
        )
        by_provider = {p or "unknown": c for p, c in prov_rows}

        # Data type counts
        pii_count = (
            session.query(func.count(DataSilo.id))
            .filter(DataSilo.contains_pii == True, DataSilo.is_active == True)  # noqa: E712
            .scalar() or 0
        )
        phi_count = (
            session.query(func.count(DataSilo.id))
            .filter(DataSilo.contains_phi == True, DataSilo.is_active == True)  # noqa: E712
            .scalar() or 0
        )
        pci_count = (
            session.query(func.count(DataSilo.id))
            .filter(DataSilo.contains_pci == True, DataSilo.is_active == True)  # noqa: E712
            .scalar() or 0
        )

        unprotected_count = len(self.unprotected(session))
        unclassified_count = len(self.unclassified(session))

        return {
            "total": total,
            "by_type": by_type,
            "by_classification": by_classification,
            "by_provider": by_provider,
            "pii_count": pii_count,
            "phi_count": phi_count,
            "pci_count": pci_count,
            "unprotected": unprotected_count,
            "unclassified": unclassified_count,
        }
