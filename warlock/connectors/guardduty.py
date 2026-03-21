"""AWS GuardDuty connector — Layer 1 implementation for cloud threat detection.

Collects active findings, detector status, and member accounts via boto3.
Requires WLK_GUARDDUTY_DETECTOR_ID and standard AWS credentials.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import boto3
except ImportError:
    boto3 = None  # type: ignore[assignment]


class GuardDutyConnector(BaseConnector):
    """Collects compliance telemetry from AWS GuardDuty."""

    def validate(self) -> list[str]:
        errors = []
        if boto3 is None:
            errors.append("boto3 not installed. Install with: pip install warlock[aws]")
        if not self.get_secret("WLK_GUARDDUTY_DETECTOR_ID"):
            errors.append("WLK_GUARDDUTY_DETECTOR_ID not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client("guardduty")
            detector_id = self.get_secret("WLK_GUARDDUTY_DETECTOR_ID")
            client.get_detector(DetectorId=detector_id)
            return True
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="guardduty",
            source_type=SourceType.CLOUD,
            provider="guardduty",
        )

        detector_id = self.get_secret("WLK_GUARDDUTY_DETECTOR_ID")

        self._collect_findings(detector_id, result)
        self._collect_detector_status(detector_id, result)
        self._collect_members(detector_id, result)

        result.complete()
        return result

    # -- Client --

    def _client(self, service: str = "guardduty"):
        """Build a boto3 client for the given service."""
        kwargs: dict = {}
        role_arn = self.config.settings.get("assume_role_arn", "")
        if role_arn:
            sts = boto3.client("sts")
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="warlock-guardduty")[
                "Credentials"
            ]
            kwargs["aws_access_key_id"] = creds["AccessKeyId"]
            kwargs["aws_secret_access_key"] = creds["SecretAccessKey"]
            kwargs["aws_session_token"] = creds["SessionToken"]
        region = self.config.settings.get("region", "us-east-1")
        kwargs["region_name"] = region
        return boto3.client(service, **kwargs)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="guardduty",
            source_type=SourceType.CLOUD,
            provider="guardduty",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_findings(self, detector_id: str, result: ConnectorResult) -> None:
        """Collect active GuardDuty findings."""
        try:
            client = self._client()
            # List finding IDs with pagination
            finding_ids: list[str] = []
            paginator = client.get_paginator("list_findings")
            for page in paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "service.archived": {
                            "Eq": ["false"],
                        }
                    }
                },
            ):
                finding_ids.extend(page.get("FindingIds", []))

            # Get full finding details in batches of 50
            findings: list[dict] = []
            for i in range(0, len(finding_ids), 50):
                batch = finding_ids[i : i + 50]
                resp = client.get_findings(DetectorId=detector_id, FindingIds=batch)
                findings.extend(resp.get("Findings", []))

            result.events.append(
                self._raw_event(
                    "guardduty_findings",
                    {"detector_id": detector_id, "findings": findings},
                )
            )
        except Exception as e:
            log.debug("GuardDuty findings collection failed: %s", e)
            result.errors.append(f"guardduty_findings: {e}")

    def _collect_detector_status(self, detector_id: str, result: ConnectorResult) -> None:
        """Collect detector configuration and status."""
        try:
            client = self._client()
            resp = client.get_detector(DetectorId=detector_id)
            # Remove ResponseMetadata to keep data clean
            resp.pop("ResponseMetadata", None)
            result.events.append(
                self._raw_event(
                    "guardduty_detector_status",
                    {"detector_id": detector_id, "detector": resp},
                )
            )
        except Exception as e:
            log.debug("GuardDuty detector status collection failed: %s", e)
            result.errors.append(f"guardduty_detector_status: {e}")

    def _collect_members(self, detector_id: str, result: ConnectorResult) -> None:
        """Collect member accounts (for multi-account setups)."""
        try:
            client = self._client()
            members: list[dict] = []
            paginator = client.get_paginator("list_members")
            for page in paginator.paginate(DetectorId=detector_id):
                members.extend(page.get("Members", []))

            result.events.append(
                self._raw_event(
                    "guardduty_members",
                    {"detector_id": detector_id, "members": members},
                )
            )
        except Exception as e:
            log.debug("GuardDuty members collection failed: %s", e)
            result.errors.append(f"guardduty_members: {e}")


# Register
registry.register("guardduty", GuardDutyConnector)
