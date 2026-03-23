"""Vanta normalizer — transforms raw Vanta API responses into Findings.

Normalizes resources as inventory and test results as policy_violation when failing.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class VantaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "vanta_resources": "_normalize_resources",
        "vanta_results": "_normalize_results",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vanta" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vanta",
            "source_type": SourceType.GRC,
            "provider": "vanta",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_resources(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for resource in items:
            resource_id = str(resource.get("uid", resource.get("id", "")))
            name = resource.get("displayName", resource.get("name", "unknown"))
            resource_type = resource.get("resourceType", resource.get("type", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vanta resource: {name}",
                    detail={
                        "resource_id": resource_id,
                        "name": name,
                        "resource_type": resource_type,
                        "integration": resource.get("integration", ""),
                        "external_url": resource.get("externalUrl", ""),
                    },
                    resource_id=resource_id,
                    resource_type=f"vanta_{resource_type.lower().replace(' ', '_')}",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_results(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for result in items:
            result_id = str(result.get("uid", result.get("id", "")))
            test_name = result.get("testName", result.get("name", "unknown"))
            outcome = result.get("outcome", result.get("status", "passing"))
            failing = str(outcome).lower() in ("failing", "fail", "failed", "error")

            obs_type = "policy_violation" if failing else "inventory"
            severity = "high" if failing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Vanta test result: {test_name}",
                    detail={
                        "result_id": result_id,
                        "test_name": test_name,
                        "outcome": outcome,
                        "description": result.get("description", ""),
                        "control_id": str(result.get("controlId", result.get("control_id", ""))),
                        "remediation": result.get("remediationGuidance", ""),
                    },
                    resource_id=result_id,
                    resource_type="vanta_test_result",
                    resource_name=test_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VantaNormalizer())
