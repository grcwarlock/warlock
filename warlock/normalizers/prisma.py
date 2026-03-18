"""Prisma Cloud normalizer — transforms raw Prisma Cloud responses into Findings.

Handles alerts, compliance posture, and asset inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PrismaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "prisma_alerts": "_normalize_alerts",
        "prisma_compliance": "_normalize_compliance",
        "prisma_assets": "_normalize_assets",
        "prisma_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "prisma" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Prisma findings."""
        return {
            "raw_event_id": raw.id,
            "source": "prisma",
            "source_type": SourceType.CSPM,
            "provider": "prisma",
            "observed_at": raw.observed_at,
        }

    @staticmethod
    def _prisma_severity(sev: str) -> str:
        """Map Prisma severity to standard severity."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
        }
        return mapping.get(sev.lower(), "medium") if sev else "medium"

    # -- Alerts --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        """One finding per Prisma Cloud alert."""
        findings = []
        alerts = raw.raw_data.get("alerts", [])

        for alert in alerts:
            severity = self._prisma_severity(alert.get("policy", {}).get("severity", ""))
            policy = alert.get("policy", {})
            resource = alert.get("resource", {})
            risk_detail = alert.get("riskDetail", {})

            # Determine observation type from policy type
            policy_type = policy.get("policyType", "").upper()
            obs_type = "alert"
            if policy_type in ("CONFIG", "CLOUD_CONFIGURATION"):
                obs_type = "misconfiguration"
            elif policy_type == "NETWORK":
                obs_type = "misconfiguration"
            elif policy_type == "AUDIT_EVENT":
                obs_type = "access_anomaly"
            elif policy_type == "IAM":
                obs_type = "policy_violation"
            elif policy_type == "ANOMALY":
                obs_type = "access_anomaly"

            alert_title = policy.get("name", "") or alert.get("reason", "Prisma Alert")

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=alert_title,
                detail={
                    "alert_id": alert.get("id", ""),
                    "alert_status": alert.get("status", ""),
                    "alert_time": alert.get("alertTime", ""),
                    "policy_id": policy.get("policyId", ""),
                    "policy_name": policy.get("name", ""),
                    "policy_type": policy.get("policyType", ""),
                    "policy_description": policy.get("description", ""),
                    "recommendation": policy.get("recommendation", ""),
                    "compliance_metadata": policy.get("complianceMetadata", []),
                    "resource_id": resource.get("id", ""),
                    "resource_name": resource.get("name", ""),
                    "resource_type": resource.get("resourceType", ""),
                    "resource_region": resource.get("region", ""),
                    "resource_account": resource.get("account", ""),
                    "resource_cloud_type": resource.get("cloudType", ""),
                    "risk_score": risk_detail.get("riskScore", {}).get("score", 0),
                },
                resource_id=resource.get("rrn", resource.get("id", "")),
                resource_type=resource.get("resourceType", ""),
                resource_name=resource.get("name", ""),
                region=resource.get("region", ""),
                account_id=resource.get("accountId", resource.get("account", "")),
                severity=severity,
            ))

        return findings

    # -- Compliance --

    def _normalize_compliance(self, raw: RawEventData) -> list[FindingData]:
        """Normalize compliance posture into findings per failed requirement."""
        findings = []
        compliance = raw.raw_data.get("compliance", {})

        # Posture response has requirementSummaries
        requirements = compliance.get("requirementSummaries", [])
        if not requirements:
            # Also try complianceSummaries
            summaries = compliance.get("complianceSummaries", [])
            for summary in summaries:
                standard = summary.get("name", "Unknown Standard")
                passed = summary.get("passedResources", 0)
                failed = summary.get("failedResources", 0)
                total = passed + failed

                if failed == 0:
                    continue

                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"Compliance: {standard} — {failed}/{total} resources failing",
                    detail={
                        "standard": standard,
                        "passed": passed,
                        "failed": failed,
                        "total": total,
                        "id": summary.get("id", ""),
                    },
                    resource_id=summary.get("id", standard),
                    resource_type="compliance_standard",
                    resource_name=standard,
                    severity="high" if failed > 0 else "info",
                ))
            return findings

        for req in requirements:
            req_name = req.get("name", "")
            req_id = req.get("id", "")
            passed = req.get("passedResources", 0)
            failed = req.get("failedResources", 0)

            if failed == 0:
                continue

            findings.append(FindingData(
                **self._base(raw),
                observation_type="policy_violation",
                title=f"Compliance: {req_name} — {failed} resources failing",
                detail={
                    "requirement_id": req_id,
                    "requirement_name": req_name,
                    "passed": passed,
                    "failed": failed,
                    "standard": req.get("standardName", ""),
                    "section": req.get("sectionId", ""),
                },
                resource_id=req_id,
                resource_type="compliance_requirement",
                resource_name=req_name,
                severity="high",
            ))

        return findings

    # -- Assets --

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        """Normalize asset inventory summary."""
        findings = []
        inventory = raw.raw_data.get("inventory", {})

        # Inventory response has groupedAggregates or resources
        resources = inventory.get("resources", [])
        if not resources:
            # Summary-level: groupedAggregates by service
            aggregates = inventory.get("groupedAggregates", [])
            for agg in aggregates:
                service = agg.get("cloudTypeName", "") or agg.get("serviceName", "Unknown")
                total = agg.get("totalResources", 0)
                passed = agg.get("passedResources", 0)
                failed = agg.get("failedResources", 0)

                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Asset summary: {service} — {total} resources ({failed} failing)",
                    detail={
                        "service": service,
                        "total_resources": total,
                        "passed_resources": passed,
                        "failed_resources": failed,
                        "high_severity_failed": agg.get("highSeverityFailedResources", 0),
                        "medium_severity_failed": agg.get("mediumSeverityFailedResources", 0),
                        "low_severity_failed": agg.get("lowSeverityFailedResources", 0),
                        "cloud_type": agg.get("cloudTypeName", ""),
                    },
                    resource_id=service,
                    resource_type="asset_summary",
                    resource_name=service,
                    severity="info",
                ))
            return findings

        for resource in resources:
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Asset: {resource.get('name', resource.get('id', '?'))}",
                detail={
                    "resource_id": resource.get("id", ""),
                    "name": resource.get("name", ""),
                    "resource_type": resource.get("resourceType", ""),
                    "cloud_type": resource.get("cloudType", ""),
                    "region": resource.get("regionId", ""),
                    "account_id": resource.get("accountId", ""),
                    "account_name": resource.get("accountName", ""),
                },
                resource_id=resource.get("rrn", resource.get("id", "")),
                resource_type=resource.get("resourceType", ""),
                resource_name=resource.get("name", ""),
                region=resource.get("regionId", ""),
                account_id=resource.get("accountId", ""),
                severity="info",
            ))

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """Policies as inventory reference data."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Policy: {policy.get('name', '?')}",
                detail={
                    "policy_id": policy.get("policyId", ""),
                    "name": policy.get("name", ""),
                    "policy_type": policy.get("policyType", ""),
                    "severity": policy.get("severity", ""),
                    "enabled": policy.get("enabled", False),
                    "cloud_type": policy.get("cloudType", ""),
                    "description": policy.get("description", ""),
                    "rule_type": policy.get("rule", {}).get("type", ""),
                    "compliance_metadata": policy.get("complianceMetadata", []),
                },
                resource_id=policy.get("policyId", ""),
                resource_type="policy",
                resource_name=policy.get("name", ""),
                severity="info",
            ))

        return findings


# Register
registry.register(PrismaNormalizer())
