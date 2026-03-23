"""Drata API normalizer — transforms raw Drata extended API responses into Findings.

Normalizes controls as inventory; tests with failures as policy_violation;
evidence as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DrataApiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "drata_api_controls": "_normalize_controls",
        "drata_api_tests": "_normalize_tests",
        "drata_api_evidence": "_normalize_evidence",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "drata_api" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "drata_api",
            "source_type": SourceType.GRC,
            "provider": "drata_api",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_controls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for control in items:
            control_id = str(control.get("id", control.get("slug", "")))
            name = control.get("name", control.get("title", "unknown"))
            status = control.get("status", "passing")
            passing = str(status).lower() in ("passing", "pass", "compliant", "active")

            obs_type = "policy_violation" if not passing else "inventory"
            severity = "high" if not passing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Drata API control: {name}",
                    detail={
                        "control_id": control_id,
                        "name": name,
                        "status": status,
                        "description": control.get("description", ""),
                        "framework": control.get("framework", ""),
                        "owner": control.get("owner", {}).get("name", "")
                        if isinstance(control.get("owner"), dict)
                        else "",
                    },
                    resource_id=control_id,
                    resource_type="drata_api_control",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_tests(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for test in items:
            test_id = str(test.get("id", ""))
            name = test.get("name", test.get("title", "unknown"))
            status = test.get("status", "passing")
            failing = str(status).lower() in ("failing", "fail", "failed", "error", "na")

            obs_type = "policy_violation" if failing else "inventory"
            severity = "high" if failing else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Drata API test: {name}",
                    detail={
                        "test_id": test_id,
                        "name": name,
                        "status": status,
                        "description": test.get("description", ""),
                        "control_id": str(test.get("controlId", "")),
                        "last_run": test.get("lastRunAt", test.get("lastChecked", "")),
                        "remediation": test.get("remediationGuidance", ""),
                    },
                    resource_id=test_id,
                    resource_type="drata_api_test",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_evidence(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for evidence in items:
            evidence_id = str(evidence.get("id", ""))
            name = evidence.get("name", evidence.get("title", "unknown"))
            file_type = evidence.get("fileType", evidence.get("type", ""))
            control_id = str(evidence.get("controlId", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Drata evidence: {name}",
                    detail={
                        "evidence_id": evidence_id,
                        "name": name,
                        "file_type": file_type,
                        "control_id": control_id,
                        "uploaded_at": evidence.get("uploadedAt", evidence.get("createdAt", "")),
                        "description": evidence.get("description", ""),
                    },
                    resource_id=evidence_id,
                    resource_type="drata_evidence",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(DrataApiNormalizer())
