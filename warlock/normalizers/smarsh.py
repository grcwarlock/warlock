"""Smarsh normalizer — transforms raw Smarsh API responses into Findings.

Normalizes communication archives (as inventory), retention policies (as inventory),
and violations (as alert, since they represent policy non-compliance events).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SmarshNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "smarsh_archives": "_normalize_archives",
        "smarsh_policies": "_normalize_policies",
        "smarsh_violations": "_normalize_violations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "smarsh" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "smarsh",
            "source_type": SourceType.COLLABORATION,
            "provider": "smarsh",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_archives(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for archive in items:
            archive_id = str(archive.get("id", ""))
            name = archive.get("name", "unknown")
            channel = archive.get("channel", "")
            status = archive.get("status", "active")
            retention_days = archive.get("retention_days", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Smarsh archive: {name}",
                    detail={
                        "archive_id": archive_id,
                        "name": name,
                        "channel": channel,
                        "status": status,
                        "retention_days": retention_days,
                        "created_at": archive.get("created_at", ""),
                    },
                    resource_id=archive_id,
                    resource_type="smarsh_archive",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            policy_type = policy.get("type", "")
            enabled = policy.get("enabled", True)
            channels = policy.get("channels", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Smarsh policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "type": policy_type,
                        "enabled": enabled,
                        "channel_count": len(channels) if isinstance(channels, list) else 0,
                        "description": policy.get("description", ""),
                    },
                    resource_id=policy_id,
                    resource_type="smarsh_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_violations(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        _severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }

        for violation in items:
            violation_id = str(violation.get("id", ""))
            description = violation.get("description", "Unknown violation")
            severity_raw = violation.get("severity", "low").lower()
            policy_name = violation.get("policy_name", "")
            user_id = violation.get("user_id", "")
            detected_at = violation.get("detected_at", "")

            severity = _severity_map.get(severity_raw, "low")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Smarsh violation: {description}",
                    detail={
                        "violation_id": violation_id,
                        "description": description,
                        "severity": severity_raw,
                        "policy_name": policy_name,
                        "user_id": user_id,
                        "detected_at": detected_at,
                        "status": violation.get("status", "open"),
                    },
                    resource_id=violation_id,
                    resource_type="smarsh_violation",
                    resource_name=description,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SmarshNormalizer())
