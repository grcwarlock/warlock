"""AWS Secrets Manager normalizer — transforms raw Secrets Manager metadata into Findings.

Normalizes secrets as misconfiguration (rotation overdue >90 days or disabled)
or inventory (rotation current). Secret values are never present in findings.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_ROTATION_OVERDUE_DAYS = 90


def _days_since_rotation(last_rotated: str | None) -> int | None:
    """Return days since last rotation. None if the field is absent."""
    if not last_rotated:
        return None
    try:
        rotated_at = datetime.fromisoformat(str(last_rotated).replace("Z", "+00:00"))
        if rotated_at.tzinfo is None:
            rotated_at = rotated_at.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - rotated_at
        return delta.days
    except (ValueError, TypeError):
        return None


class AwsSecretsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "aws_secrets_metadata": "_normalize_secrets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aws_secrets" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "aws_secrets",
            "source_type": SourceType.CLOUD,
            "provider": "aws_secrets",
            "account_id": "",
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Secrets --

    def _normalize_secrets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for secret in items:
            # Never access SecretString or SecretBinary — only metadata
            secret_arn = secret.get("ARN", "")
            name = secret.get("Name", "unknown")
            rotation_enabled = secret.get("RotationEnabled", False)
            last_rotated = secret.get("LastRotatedDate", "")
            last_changed = secret.get("LastChangedDate", "")
            description = secret.get("Description", "")
            kms_key_id = secret.get("KmsKeyId", "")
            tags = secret.get("Tags", [])

            # Short ID from ARN
            secret_id = secret_arn.split(":")[-1] if ":" in secret_arn else name

            days_since = _days_since_rotation(last_rotated or last_changed)

            if not rotation_enabled:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"AWS secret rotation disabled: {name}"
            elif days_since is not None and days_since > _ROTATION_OVERDUE_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"AWS secret rotation overdue ({days_since}d): {name}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"AWS secret: {name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "secret_arn": secret_arn,
                        "name": name,
                        "rotation_enabled": rotation_enabled,
                        "last_rotated": str(last_rotated) if last_rotated else "",
                        "last_changed": str(last_changed) if last_changed else "",
                        "days_since_rotation": days_since,
                        "description": description,
                        "kms_key_id": kms_key_id,
                        "tag_count": len(tags) if isinstance(tags, list) else 0,
                    },
                    resource_id=secret_id,
                    resource_type="aws_secret",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AwsSecretsNormalizer())
