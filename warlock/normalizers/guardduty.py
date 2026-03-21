"""GuardDuty normalizer — transforms raw GuardDuty API responses into Findings.

Maps GuardDuty severity (0-8.9 scale) to warlock severity, flags high/critical
findings, disabled detectors, and extracts resource details.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


def _map_severity(gd_severity: float) -> str:
    """Map GuardDuty numeric severity (0-8.9) to warlock severity string.

    GuardDuty scale:
        0.0-3.9  = Low
        4.0-6.9  = Medium
        7.0-8.9  = High
    We split High into high (7.0-7.9) and critical (8.0-8.9).
    """
    if gd_severity >= 8.0:
        return "critical"
    if gd_severity >= 7.0:
        return "high"
    if gd_severity >= 4.0:
        return "medium"
    if gd_severity >= 1.0:
        return "low"
    return "info"


def _extract_resource_id(resource: dict) -> str:
    """Extract the primary resource identifier from a GuardDuty resource block."""
    # Try instance ID first
    instance_details = resource.get("InstanceDetails", {})
    if instance_details and instance_details.get("InstanceId"):
        return instance_details["InstanceId"]

    # Try S3 bucket
    s3_details = resource.get("S3BucketDetails", [])
    if s3_details and isinstance(s3_details, list) and len(s3_details) > 0:
        return s3_details[0].get("Name", "")

    # Try access key / IAM
    access_key = resource.get("AccessKeyDetails", {})
    if access_key and access_key.get("AccessKeyId"):
        return access_key["AccessKeyId"]

    # Try EKS cluster
    eks_details = resource.get("EksClusterDetails", {})
    if eks_details and eks_details.get("Name"):
        return eks_details["Name"]

    # Try container
    container = resource.get("ContainerDetails", {})
    if container and container.get("Id"):
        return container["Id"]

    # Fallback to resource type
    return resource.get("ResourceType", "unknown")


def _extract_resource_type(resource: dict) -> str:
    """Map GuardDuty resource type to a warlock resource type string."""
    rt = resource.get("ResourceType", "")
    type_map = {
        "Instance": "aws_ec2_instance",
        "AccessKey": "aws_iam_access_key",
        "S3Bucket": "aws_s3_bucket",
        "EKSCluster": "aws_eks_cluster",
        "Container": "aws_container",
        "RDSDBInstance": "aws_rds_instance",
        "Lambda": "aws_lambda_function",
        "ECSCluster": "aws_ecs_cluster",
    }
    return type_map.get(rt, f"aws_{rt.lower()}" if rt else "aws_resource")


class GuardDutyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "guardduty_findings": "_normalize_findings",
        "guardduty_detector_status": "_normalize_detector_status",
        "guardduty_members": "_normalize_members",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "guardduty" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all GuardDuty findings."""
        return {
            "raw_event_id": raw.id,
            "source": "guardduty",
            "source_type": SourceType.CLOUD,
            "provider": "guardduty",
            "observed_at": raw.observed_at,
        }

    # -- Findings --

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        """Normalize GuardDuty findings into warlock findings."""
        findings = []
        detector_id = raw.raw_data.get("detector_id", "")
        gd_findings = raw.raw_data.get("findings", [])

        for gd in gd_findings:
            finding_id = gd.get("Id", "")
            finding_type = gd.get("Type", "")
            title = gd.get("Title", finding_type)
            description = gd.get("Description", "")
            gd_severity = gd.get("Severity", 0.0)
            severity = _map_severity(float(gd_severity))
            confidence = gd.get("Confidence", 0.0)
            resource = gd.get("Resource", {})
            service = gd.get("Service", {})
            account_id = gd.get("AccountId", "")
            region = gd.get("Region", "")
            created_at = gd.get("CreatedAt", "")
            updated_at = gd.get("UpdatedAt", "")

            resource_id = _extract_resource_id(resource)
            resource_type = _extract_resource_type(resource)

            # Determine observation type based on finding category
            action = service.get("Action", {})
            action_type = action.get("ActionType", "")

            if "Recon" in finding_type or "Discovery" in finding_type:
                obs_type = "alert"
            elif "UnauthorizedAccess" in finding_type or "Policy" in finding_type:
                obs_type = "policy_violation"
            elif (
                "Backdoor" in finding_type
                or "Trojan" in finding_type
                or "CryptoCurrency" in finding_type
            ):
                obs_type = "alert"
            else:
                obs_type = "alert"

            # Inventory finding for every detection
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"GuardDuty: {title}",
                    detail={
                        "finding_id": finding_id,
                        "finding_type": finding_type,
                        "description": description,
                        "guardduty_severity": gd_severity,
                        "confidence": confidence,
                        "resource_type": resource.get("ResourceType", ""),
                        "resource_id": resource_id,
                        "action_type": action_type,
                        "service_name": service.get("ServiceName", ""),
                        "count": service.get("Count", 1),
                        "created_at": created_at,
                        "updated_at": updated_at,
                        "detector_id": detector_id,
                    },
                    resource_id=resource_id,
                    resource_type=resource_type,
                    resource_name=resource_id,
                    account_id=account_id,
                    region=region,
                    severity=severity,
                    confidence=min(confidence / 100.0, 1.0) if confidence > 1 else confidence,
                )
            )

        return findings

    # -- Detector Status --

    def _normalize_detector_status(self, raw: RawEventData) -> list[FindingData]:
        """Check detector status; flag disabled or misconfigured detectors."""
        findings = []
        detector_id = raw.raw_data.get("detector_id", "")
        detector = raw.raw_data.get("detector", {})

        status = detector.get("Status", "")
        created_at = detector.get("CreatedAt", "")
        finding_frequency = detector.get("FindingPublishingFrequency", "")
        data_sources = detector.get("DataSources", {})
        features = detector.get("Features", [])

        # Inventory
        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"GuardDuty detector: {status}",
                detail={
                    "detector_id": detector_id,
                    "status": status,
                    "created_at": created_at,
                    "finding_publishing_frequency": finding_frequency,
                    "data_sources": data_sources,
                    "features": [f.get("Name", "") for f in features]
                    if isinstance(features, list)
                    else [],
                },
                resource_id=detector_id,
                resource_type="aws_guardduty_detector",
                resource_name=f"detector:{detector_id}",
                account_id="",
                severity="info",
            )
        )

        # Flag disabled detector
        if status and status.upper() != "ENABLED":
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"GuardDuty detector disabled: {detector_id}",
                    detail={
                        "detector_id": detector_id,
                        "status": status,
                        "issue": "GuardDuty detector is not enabled — threat detection is inactive",
                    },
                    resource_id=detector_id,
                    resource_type="aws_guardduty_detector",
                    resource_name=f"detector:{detector_id}",
                    account_id="",
                    severity="critical",
                )
            )

        # Flag infrequent publishing
        if finding_frequency and finding_frequency != "FIFTEEN_MINUTES":
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"GuardDuty finding publish frequency: {finding_frequency}",
                    detail={
                        "detector_id": detector_id,
                        "finding_publishing_frequency": finding_frequency,
                        "expected": "FIFTEEN_MINUTES",
                        "issue": "Finding publishing frequency is not set to the most frequent interval",
                    },
                    resource_id=detector_id,
                    resource_type="aws_guardduty_detector",
                    resource_name=f"detector:{detector_id}",
                    account_id="",
                    severity="low",
                )
            )

        # Flag disabled data sources / features
        if isinstance(features, list):
            for feat in features:
                feat_name = feat.get("Name", "")
                feat_status = feat.get("Status", "")
                if feat_status and feat_status.upper() != "ENABLED":
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="misconfiguration",
                            title=f"GuardDuty feature disabled: {feat_name}",
                            detail={
                                "detector_id": detector_id,
                                "feature_name": feat_name,
                                "feature_status": feat_status,
                                "issue": f"GuardDuty feature '{feat_name}' is not enabled — reduces detection coverage",
                            },
                            resource_id=detector_id,
                            resource_type="aws_guardduty_detector",
                            resource_name=f"detector:{detector_id}",
                            account_id="",
                            severity="medium",
                        )
                    )

        return findings

    # -- Members --

    def _normalize_members(self, raw: RawEventData) -> list[FindingData]:
        """Inventory member accounts."""
        findings = []
        detector_id = raw.raw_data.get("detector_id", "")
        members = raw.raw_data.get("members", [])

        for member in members:
            member_id = member.get("AccountId", "")
            email = member.get("Email", "")
            relationship = member.get("RelationshipStatus", "")
            invited_at = member.get("InvitedAt", "")
            updated_at = member.get("UpdatedAt", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GuardDuty member: {member_id} ({relationship})",
                    detail={
                        "account_id": member_id,
                        "email": email,
                        "relationship_status": relationship,
                        "invited_at": invited_at,
                        "updated_at": updated_at,
                        "detector_id": detector_id,
                    },
                    resource_id=member_id,
                    resource_type="aws_account",
                    resource_name=email or member_id,
                    account_id=member_id,
                    severity="info",
                )
            )

            # Flag members not in "Enabled" relationship
            if relationship and relationship not in ("Enabled", "Created"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"GuardDuty member not active: {member_id} ({relationship})",
                        detail={
                            "account_id": member_id,
                            "email": email,
                            "relationship_status": relationship,
                            "issue": f"Member account relationship is '{relationship}' — GuardDuty may not be monitoring this account",
                            "detector_id": detector_id,
                        },
                        resource_id=member_id,
                        resource_type="aws_account",
                        resource_name=email or member_id,
                        account_id=member_id,
                        severity="medium",
                    )
                )

        return findings


# Register
registry.register(GuardDutyNormalizer())
