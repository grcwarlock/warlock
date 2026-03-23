"""GCP Secret Manager normalizer — transforms raw Secret Manager metadata into Findings.

Normalizes secrets as misconfiguration (rotation overdue >90 days or no rotation
configured) or inventory (rotation current). Secret values are never present
in findings.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_ROTATION_OVERDUE_DAYS = 90


def _days_since(timestamp: str | None) -> int | None:
    """Return days since an ISO-8601 RFC3339 timestamp. None if absent."""
    if not timestamp:
        return None
    try:
        dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


class GcpSecretsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gcp_secrets_metadata": "_normalize_secrets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gcp_secrets" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "gcp_secrets",
            "source_type": SourceType.CLOUD,
            "provider": "gcp_secrets",
            "account_id": raw.raw_data.get("project_id", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Secrets --

    def _normalize_secrets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for secret in items:
            # GCP secret name format: projects/{project}/secrets/{secret-id}
            full_name = secret.get("name", "")
            name = full_name.rsplit("/", 1)[-1] if "/" in full_name else full_name
            create_time = secret.get("createTime", "")
            labels = secret.get("labels", {})
            replication = secret.get("replication", {})
            rotation = secret.get("rotation", {})
            expire_time = secret.get("expireTime", "")

            # Determine rotation health
            rotation_period = rotation.get("rotationPeriod") if isinstance(rotation, dict) else None
            next_rotation = rotation.get("nextRotationTime") if isinstance(rotation, dict) else None

            days_since_create = _days_since(create_time)

            # Check if rotation is configured at all
            has_rotation = bool(rotation_period or next_rotation)

            if not has_rotation and days_since_create is not None and days_since_create > _ROTATION_OVERDUE_DAYS:
                obs_type = "misconfiguration"
                severity = "medium"
                title = f"GCP secret no rotation configured ({days_since_create}d old): {name}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"GCP secret: {name}"

            replication_type = "unknown"
            if isinstance(replication, dict):
                if "automatic" in replication:
                    replication_type = "automatic"
                elif "userManaged" in replication:
                    replication_type = "user_managed"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "secret_name": full_name,
                        "name": name,
                        "create_time": create_time,
                        "days_since_create": days_since_create,
                        "has_rotation": has_rotation,
                        "rotation_period": rotation_period,
                        "next_rotation": next_rotation,
                        "expire_time": expire_time,
                        "replication_type": replication_type,
                        "label_count": len(labels) if isinstance(labels, dict) else 0,
                    },
                    resource_id=name,
                    resource_type="gcp_secret",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(GcpSecretsNormalizer())
