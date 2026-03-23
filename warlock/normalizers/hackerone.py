"""HackerOne normalizer — transforms raw HackerOne API responses into Findings.

Normalizes vulnerability reports as vulnerability findings with severity from the provider,
programs and hackers as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "info",
    "informational": "info",
}


class HackerOneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for HackerOne bug bounty findings."""

    HANDLERS: dict[str, str] = {
        "hackerone_reports": "_normalize_reports",
        "hackerone_programs": "_normalize_programs",
        "hackerone_hackers": "_normalize_hackers",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "hackerone" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "hackerone",
            "source_type": SourceType.CUSTOM,
            "provider": "hackerone",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_reports(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for report in items:
            attributes = report.get("attributes", report)
            report_id = str(report.get("id", ""))
            title = attributes.get("title", "HackerOne Report")
            state = attributes.get("state", "")

            # Severity from nested relationships
            severity_rel = report.get("relationships", {}).get("severity", {}).get("data", {})
            severity_attrs = (
                severity_rel.get("attributes", {}) if isinstance(severity_rel, dict) else {}
            )
            severity_raw = str(
                severity_attrs.get("rating", attributes.get("severity", "low"))
            ).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"HackerOne report: {title}",
                    detail={
                        "report_id": report_id,
                        "title": title,
                        "state": state,
                        "severity": severity_raw,
                        "weakness": report.get("relationships", {})
                        .get("weakness", {})
                        .get("data", {})
                        .get("attributes", {})
                        .get("name", ""),
                        "bounty_amount": attributes.get("bounty_amount", 0),
                        "created_at": attributes.get("created_at", ""),
                        "disclosed_at": attributes.get("disclosed_at", ""),
                        "reporter": report.get("relationships", {})
                        .get("reporter", {})
                        .get("data", {})
                        .get("attributes", {})
                        .get("username", ""),
                    },
                    resource_id=report_id,
                    resource_type="hackerone_report",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_programs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for program in items:
            attributes = program.get("attributes", program)
            program_id = str(program.get("id", ""))
            name = attributes.get("name", attributes.get("handle", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"HackerOne program: {name}",
                    detail={
                        "program_id": program_id,
                        "name": name,
                        "handle": attributes.get("handle", ""),
                        "state": attributes.get("state", ""),
                        "offers_bounties": attributes.get("offers_bounties", False),
                        "total_bounties_paid": attributes.get("total_bounties_paid_in_cents", 0),
                        "report_count": attributes.get("number_of_reports_for_user", 0),
                        "created_at": attributes.get("created_at", ""),
                    },
                    resource_id=program_id,
                    resource_type="hackerone_program",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_hackers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for hacker in items:
            attributes = hacker.get("attributes", hacker)
            hacker_id = str(hacker.get("id", ""))
            username = attributes.get("username", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"HackerOne hacker: {username}",
                    detail={
                        "hacker_id": hacker_id,
                        "username": username,
                        "reputation": attributes.get("reputation", 0),
                        "signal": attributes.get("signal", 0),
                        "impact": attributes.get("impact", 0),
                        "rank": attributes.get("rank", 0),
                        "reports_count": attributes.get("reports_sent_count", 0),
                        "website": attributes.get("website", ""),
                    },
                    resource_id=hacker_id,
                    resource_type="hackerone_hacker",
                    resource_name=username,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HackerOneNormalizer())
