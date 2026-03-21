"""GitGuardian normalizer — transforms raw GitGuardian API responses into Findings.

Handles incidents, members, and sources.
Flags: open incidents (unresolved secrets), critical detector matches,
repos without scanning.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GitGuardianNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gitguardian_incidents": "_normalize_incidents",
        "gitguardian_members": "_normalize_members",
        "gitguardian_sources": "_normalize_sources",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gitguardian" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all GitGuardian findings."""
        return {
            "raw_event_id": raw.id,
            "source": "gitguardian",
            "source_type": SourceType.CODE,
            "provider": "gitguardian",
            "observed_at": raw.observed_at,
        }

    # -- Incidents --

    def _normalize_incidents(self, raw: RawEventData) -> list[FindingData]:
        """Normalize secret leak incidents; flag open/unresolved ones."""
        findings = []
        incidents = raw.raw_data.get("incidents", [])

        for incident in incidents:
            incident_id = str(incident.get("id", ""))
            detector_name = incident.get("detector", {}).get("name", "")
            if isinstance(incident.get("detector"), str):
                detector_name = incident.get("detector", "")
            detector_group = incident.get("detector", {}).get("group_name", "") if isinstance(incident.get("detector"), dict) else ""
            status = incident.get("status", incident.get("assignee_email", ""))
            severity = incident.get("severity", "high").lower()
            date_created = incident.get("date", incident.get("created_at", ""))
            occurrences_count = incident.get("occurrences_count", incident.get("total_occurrences", 0))
            validity = incident.get("validity", "")
            repo_name = ""
            if incident.get("occurrences"):
                first_occ = incident["occurrences"][0] if incident["occurrences"] else {}
                repo_name = first_occ.get("source", {}).get("name", "") if isinstance(first_occ.get("source"), dict) else ""

            # Inventory every incident
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Secret leak: {detector_name} ({status})",
                    detail={
                        "incident_id": incident_id,
                        "detector_name": detector_name,
                        "detector_group": detector_group,
                        "status": status,
                        "severity": severity,
                        "date_created": date_created,
                        "occurrences_count": occurrences_count,
                        "validity": validity,
                        "repo_name": repo_name,
                    },
                    resource_id=incident_id,
                    resource_type="gitguardian_incident",
                    resource_name=f"{detector_name}:{incident_id}",
                    severity=severity if severity in ("critical", "high", "medium", "low") else "high",
                )
            )

            # Flag open/unresolved incidents
            if status not in ("RESOLVED", "resolved", "IGNORED", "ignored"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Unresolved secret leak: {detector_name}",
                        detail={
                            "incident_id": incident_id,
                            "detector_name": detector_name,
                            "status": status,
                            "severity": severity,
                            "occurrences_count": occurrences_count,
                            "validity": validity,
                            "repo_name": repo_name,
                            "issue": "Secret leak incident remains unresolved — credentials may be exposed in source control",
                        },
                        resource_id=incident_id,
                        resource_type="gitguardian_incident",
                        resource_name=f"{detector_name}:{incident_id}",
                        severity="critical" if validity == "valid" else "high",
                    )
                )

            # Flag valid (confirmed real) secrets at critical severity
            if validity == "valid" and status not in ("RESOLVED", "resolved"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Confirmed valid secret exposed: {detector_name}",
                        detail={
                            "incident_id": incident_id,
                            "detector_name": detector_name,
                            "validity": "valid",
                            "status": status,
                            "repo_name": repo_name,
                            "issue": "GitGuardian confirmed this secret is valid and active — immediate rotation required",
                        },
                        resource_id=incident_id,
                        resource_type="gitguardian_incident",
                        resource_name=f"{detector_name}:{incident_id}",
                        severity="critical",
                    )
                )

        return findings

    # -- Members --

    def _normalize_members(self, raw: RawEventData) -> list[FindingData]:
        """Inventory organization members."""
        findings = []
        members = raw.raw_data.get("members", [])

        for member in members:
            member_id = str(member.get("id", ""))
            email = member.get("email", "")
            name = member.get("name", email)
            role = member.get("role", "")
            last_login = member.get("last_login", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitGuardian member: {name} ({role})",
                    detail={
                        "member_id": member_id,
                        "email": email,
                        "name": name,
                        "role": role,
                        "last_login": last_login,
                    },
                    resource_id=member_id,
                    resource_type="gitguardian_member",
                    resource_name=name or email,
                    severity="info",
                )
            )

        return findings

    # -- Sources --

    def _normalize_sources(self, raw: RawEventData) -> list[FindingData]:
        """Inventory monitored sources (repos); flag repos without scanning."""
        findings = []
        sources = raw.raw_data.get("sources", [])

        for source in sources:
            source_id = str(source.get("id", ""))
            source_name = source.get("full_name", source.get("name", ""))
            source_type = source.get("type", "")
            health = source.get("health", source.get("status", ""))
            last_scan = source.get("last_scan", source.get("last_scan_at", ""))
            open_incidents = source.get("open_incidents_count", 0)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"GitGuardian source: {source_name}",
                    detail={
                        "source_id": source_id,
                        "source_name": source_name,
                        "source_type": source_type,
                        "health": health,
                        "last_scan": last_scan,
                        "open_incidents_count": open_incidents,
                    },
                    resource_id=source_id,
                    resource_type="gitguardian_source",
                    resource_name=source_name,
                    severity="info",
                )
            )

            # Flag repos with no scanning
            if not last_scan:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Repository without scanning: {source_name}",
                        detail={
                            "source_id": source_id,
                            "source_name": source_name,
                            "source_type": source_type,
                            "issue": "Repository is registered in GitGuardian but has never been scanned for secrets",
                        },
                        resource_id=source_id,
                        resource_type="gitguardian_source",
                        resource_name=source_name,
                        severity="high",
                    )
                )

            # Flag repos with open incidents
            if open_incidents and open_incidents > 0:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Repository with open secret incidents: {source_name}",
                        detail={
                            "source_id": source_id,
                            "source_name": source_name,
                            "open_incidents_count": open_incidents,
                            "issue": f"Repository has {open_incidents} unresolved secret leak incident(s)",
                        },
                        resource_id=source_id,
                        resource_type="gitguardian_source",
                        resource_name=source_name,
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(GitGuardianNormalizer())
