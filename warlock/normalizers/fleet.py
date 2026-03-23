"""Fleet normalizer — transforms raw Fleet API responses into Findings.

Normalizes hosts as inventory, policy violations as misconfiguration,
queries as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FleetNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Fleet MDM/osquery findings."""

    HANDLERS: dict[str, str] = {
        "fleet_hosts": "_normalize_hosts",
        "fleet_queries": "_normalize_queries",
        "fleet_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fleet" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "fleet",
            "source_type": SourceType.MDM,
            "provider": "fleet",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_hosts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("hosts", [])

        for host in items:
            host_id = str(host.get("id", ""))
            name = host.get("hostname", host.get("computer_name", "unknown"))
            platform = host.get("platform", "")
            mdm_enrolled = host.get("mdm", {}).get("enrollment_status", "") == "On (automatic)"

            # Hosts that are not MDM enrolled may be a misconfiguration concern
            severity = "low" if not mdm_enrolled and host.get("mdm") else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Fleet host: {name}",
                    detail={
                        "host_id": host_id,
                        "hostname": name,
                        "platform": platform,
                        "os_version": host.get("os_version", ""),
                        "status": host.get("status", ""),
                        "cpu_type": host.get("cpu_type", ""),
                        "mdm_status": host.get("mdm", {}).get("enrollment_status", ""),
                        "last_enrolled_at": host.get("last_enrolled_at", ""),
                        "issues": host.get("issues", {}).get("total_issues_count", 0),
                    },
                    resource_id=host_id,
                    resource_type="fleet_host",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_queries(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("queries", [])

        for query in items:
            query_id = str(query.get("id", ""))
            name = query.get("name", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Fleet query: {name}",
                    detail={
                        "query_id": query_id,
                        "name": name,
                        "description": query.get("description", ""),
                        "query": query.get("query", ""),
                        "platform": query.get("platform", ""),
                        "author": query.get("author_name", ""),
                        "created_at": query.get("created_at", ""),
                    },
                    resource_id=query_id,
                    resource_type="fleet_query",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("policies", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            passing_host_count = policy.get("passing_host_count", 0)
            failing_host_count = policy.get("failing_host_count", 0)

            # If any hosts are failing this policy, flag it as misconfiguration
            has_failures = failing_host_count > 0
            severity = "medium" if has_failures else "info"
            obs_type = "misconfiguration" if has_failures else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Fleet policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "description": policy.get("description", ""),
                        "query": policy.get("query", ""),
                        "platform": policy.get("platform", ""),
                        "passing_host_count": passing_host_count,
                        "failing_host_count": failing_host_count,
                        "author": policy.get("author_name", ""),
                    },
                    resource_id=policy_id,
                    resource_type="fleet_policy",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(FleetNormalizer())
