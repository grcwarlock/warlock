"""42Crunch normalizer — transforms raw 42Crunch API responses into Findings.

Normalizes API inventory (as inventory findings) and audit results
(as vulnerability findings with severity mapped from audit score).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FortyTwoCrunchNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for 42Crunch findings."""

    HANDLERS: dict[str, str] = {
        "fortytwocrunch_apis": "_normalize_apis",
        "fortytwocrunch_audits": "_normalize_audits",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fortytwocrunch" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "fortytwocrunch",
            "source_type": SourceType.CUSTOM,
            "provider": "fortytwocrunch",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_apis(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("apis", response.get("data", []))

        for api in items:
            api_id = str(api.get("id", api.get("api_id", "")))
            name = api.get("name", api.get("title", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"42Crunch API: {name}",
                    detail={
                        "api_id": api_id,
                        "name": name,
                        "version": api.get("version", ""),
                        "compliance_level": api.get("compliance_level", ""),
                        "tags": api.get("tags", []),
                    },
                    resource_id=api_id,
                    resource_type="api_definition",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_audits(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("audits", response.get("data", []))

        for audit in items:
            audit_id = str(audit.get("id", audit.get("audit_id", "")))
            api_name = audit.get("api_name", audit.get("name", "unknown"))
            score = audit.get("score", audit.get("security_score", 100))

            # Map score to severity: <50 = high, 50-75 = medium, >75 = low
            if isinstance(score, (int, float)):
                if score < 50:
                    severity = "high"
                elif score < 75:
                    severity = "medium"
                else:
                    severity = "low"
            else:
                severity = "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"42Crunch audit: {api_name} (score: {score})",
                    detail={
                        "audit_id": audit_id,
                        "api_name": api_name,
                        "score": score,
                        "issues": audit.get("issues", []),
                        "compliance": audit.get("compliance", {}),
                    },
                    resource_id=audit_id,
                    resource_type="api_audit",
                    resource_name=api_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FortyTwoCrunchNormalizer())
