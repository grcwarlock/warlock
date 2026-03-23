"""PlexTrac normalizer — transforms raw PlexTrac API responses into Findings.

Normalizes clients and reports (as inventory), and pentest findings (as
vulnerability with severity mapped from the PlexTrac severity field).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PlexTracNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for PlexTrac."""

    HANDLERS: dict[str, str] = {
        "plextrac_clients": "_normalize_clients",
        "plextrac_reports": "_normalize_reports",
        "plextrac_findings": "_normalize_findings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "plextrac" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "plextrac",
            "source_type": SourceType.CUSTOM,
            "provider": "plextrac",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    @staticmethod
    def _map_severity(severity: str) -> str:
        """Map PlexTrac severity labels to Warlock severity."""
        _map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
            "none": "info",
        }
        return _map.get(str(severity).lower(), "medium")

    def _normalize_clients(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for client in items:
            client_id = str(client.get("id", client.get("clientId", "")))
            name = client.get("name", client.get("clientName", "unknown"))
            tags = client.get("tags", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"PlexTrac client: {name}",
                    detail={
                        "client_id": client_id,
                        "name": name,
                        "tags": tags,
                        "created_at": client.get("createdAt", ""),
                        "description": client.get("description", ""),
                    },
                    resource_id=client_id,
                    resource_type="plextrac_client",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_reports(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for report in items:
            report_id = str(report.get("id", report.get("reportId", "")))
            name = report.get("name", report.get("reportName", "unknown"))
            status = report.get("status", "unknown")
            client_id = str(report.get("clientId", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"PlexTrac report: {name}",
                    detail={
                        "report_id": report_id,
                        "name": name,
                        "status": status,
                        "client_id": client_id,
                        "created_at": report.get("createdAt", ""),
                        "start_date": report.get("startDate", ""),
                        "end_date": report.get("endDate", ""),
                    },
                    resource_id=report_id,
                    resource_type="plextrac_report",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for item in items:
            finding_id = str(item.get("id", item.get("findingId", "")))
            title = item.get("title", item.get("findingTitle", "unknown"))
            severity_raw = str(item.get("severity", item.get("findingSeverity", "medium")))
            status = item.get("status", "open")
            description = item.get("description", "")
            report_id = str(item.get("reportId", ""))
            cve_ids = item.get("cves", item.get("cveIds", []))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"PlexTrac finding: {title}",
                    detail={
                        "finding_id": finding_id,
                        "title": title,
                        "severity": severity_raw,
                        "status": status,
                        "description": description[:500] if description else "",
                        "report_id": report_id,
                        "cve_ids": cve_ids,
                        "affected_assets": item.get("affectedAssets", []),
                    },
                    resource_id=finding_id,
                    resource_type="plextrac_finding",
                    resource_name=title,
                    severity=self._map_severity(severity_raw),
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(PlexTracNormalizer())
