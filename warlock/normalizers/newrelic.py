"""New Relic normalizer — transforms raw New Relic API responses into Findings.

Handles alert conditions, entity health, and open violations.
Flags open critical violations, unhealthy entities, and alerting conditions
without notification channels.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class NewRelicNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "newrelic_alerts": "_normalize_alerts",
        "newrelic_entities": "_normalize_entities",
        "newrelic_violations": "_normalize_violations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "newrelic" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all New Relic findings."""
        return {
            "raw_event_id": raw.id,
            "source": "newrelic",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "newrelic",
            "observed_at": raw.observed_at,
        }

    # -- Alert Conditions --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        """Inventory alert conditions; flag disabled conditions."""
        findings = []
        account_id = raw.raw_data.get("account_id", "")
        conditions = raw.raw_data.get("conditions", [])

        for cond in conditions:
            cond_id = str(cond.get("id", ""))
            name = cond.get("name", "")
            enabled = cond.get("enabled", True)
            cond_type = cond.get("type", "")
            policy_id = str(cond.get("policyId", ""))
            nrql = cond.get("nrql", {})
            nrql_query = nrql.get("query", "") if isinstance(nrql, dict) else ""
            terms = cond.get("terms", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Alert condition: {name}",
                    detail={
                        "condition_id": cond_id,
                        "name": name,
                        "enabled": enabled,
                        "type": cond_type,
                        "policy_id": policy_id,
                        "nrql_query": nrql_query,
                        "terms_count": len(terms),
                        "account_id": account_id,
                    },
                    resource_id=cond_id,
                    resource_type="newrelic_alert_condition",
                    resource_name=name,
                    account_id=account_id,
                    severity="info",
                )
            )

            # Flag disabled conditions
            if not enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Alert condition disabled: {name}",
                        detail={
                            "condition_id": cond_id,
                            "name": name,
                            "enabled": False,
                            "policy_id": policy_id,
                            "issue": "Alert condition is disabled — incidents for this condition will not fire",
                            "account_id": account_id,
                        },
                        resource_id=cond_id,
                        resource_type="newrelic_alert_condition",
                        resource_name=name,
                        account_id=account_id,
                        severity="medium",
                    )
                )

            # Flag conditions without terms (no thresholds defined)
            if not terms:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Alert condition has no thresholds: {name}",
                        detail={
                            "condition_id": cond_id,
                            "name": name,
                            "terms_count": 0,
                            "issue": "Alert condition has no threshold terms — it cannot trigger violations",
                            "account_id": account_id,
                        },
                        resource_id=cond_id,
                        resource_type="newrelic_alert_condition",
                        resource_name=name,
                        account_id=account_id,
                        severity="medium",
                    )
                )

        return findings

    # -- Entities --

    def _normalize_entities(self, raw: RawEventData) -> list[FindingData]:
        """Inventory entities; flag unhealthy or non-reporting ones."""
        findings = []
        account_id = raw.raw_data.get("account_id", "")
        entities = raw.raw_data.get("entities", [])

        for entity in entities:
            guid = entity.get("guid", "")
            name = entity.get("name", "")
            entity_type = entity.get("entityType", "")
            domain = entity.get("domain", "")
            reporting = entity.get("reporting", True)
            alert_severity = entity.get("alertSeverity", "")
            tags = entity.get("tags", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Entity: {name} ({entity_type}, {alert_severity or 'ok'})",
                    detail={
                        "guid": guid,
                        "name": name,
                        "entity_type": entity_type,
                        "domain": domain,
                        "reporting": reporting,
                        "alert_severity": alert_severity,
                        "tags": tags,
                        "account_id": account_id,
                    },
                    resource_id=guid,
                    resource_type=f"newrelic_{entity_type.lower()}"
                    if entity_type
                    else "newrelic_entity",
                    resource_name=name,
                    account_id=account_id,
                    severity="info",
                )
            )

            # Flag non-reporting entities
            if not reporting:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Entity not reporting: {name}",
                        detail={
                            "guid": guid,
                            "name": name,
                            "entity_type": entity_type,
                            "reporting": False,
                            "issue": "Entity is not reporting data — may be down or agent is disconnected",
                            "account_id": account_id,
                        },
                        resource_id=guid,
                        resource_type=f"newrelic_{entity_type.lower()}"
                        if entity_type
                        else "newrelic_entity",
                        resource_name=name,
                        account_id=account_id,
                        severity="high",
                    )
                )

            # Flag entities with critical alert severity
            if alert_severity and alert_severity.upper() == "CRITICAL":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Entity in critical state: {name}",
                        detail={
                            "guid": guid,
                            "name": name,
                            "entity_type": entity_type,
                            "alert_severity": alert_severity,
                            "issue": "Entity has active critical alert — service health is degraded",
                            "account_id": account_id,
                        },
                        resource_id=guid,
                        resource_type=f"newrelic_{entity_type.lower()}"
                        if entity_type
                        else "newrelic_entity",
                        resource_name=name,
                        account_id=account_id,
                        severity="critical",
                    )
                )
            elif alert_severity and alert_severity.upper() == "WARNING":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Entity in warning state: {name}",
                        detail={
                            "guid": guid,
                            "name": name,
                            "entity_type": entity_type,
                            "alert_severity": alert_severity,
                            "issue": "Entity has active warning alert — service health may be at risk",
                            "account_id": account_id,
                        },
                        resource_id=guid,
                        resource_type=f"newrelic_{entity_type.lower()}"
                        if entity_type
                        else "newrelic_entity",
                        resource_name=name,
                        account_id=account_id,
                        severity="medium",
                    )
                )

        return findings

    # -- Violations --

    def _normalize_violations(self, raw: RawEventData) -> list[FindingData]:
        """Normalize open violations; map priority to severity."""
        findings = []
        account_id = raw.raw_data.get("account_id", "")
        violations = raw.raw_data.get("violations", [])

        for viol in violations:
            viol_id = str(viol.get("id", ""))
            label = viol.get("label", "")
            priority = viol.get("priority", "warning").lower()
            opened_at = viol.get("opened_at", 0)
            duration = viol.get("duration", 0)
            condition_name = viol.get("condition_name", "")
            policy_name = viol.get("policy_name", "")
            entity = viol.get("entity", {})
            entity_name = entity.get("name", "") if isinstance(entity, dict) else ""
            entity_id = str(entity.get("id", "")) if isinstance(entity, dict) else ""
            entity_type = entity.get("type", "") if isinstance(entity, dict) else ""

            # Map priority to severity
            sev_map = {"critical": "critical", "warning": "medium"}
            severity = sev_map.get(priority, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Open violation: {label or condition_name} ({priority})",
                    detail={
                        "violation_id": viol_id,
                        "label": label,
                        "priority": priority,
                        "opened_at": opened_at,
                        "duration_seconds": duration,
                        "condition_name": condition_name,
                        "policy_name": policy_name,
                        "entity_name": entity_name,
                        "entity_id": entity_id,
                        "entity_type": entity_type,
                        "account_id": account_id,
                    },
                    resource_id=entity_id or viol_id,
                    resource_type=f"newrelic_{entity_type.lower()}"
                    if entity_type
                    else "newrelic_entity",
                    resource_name=entity_name or label,
                    account_id=account_id,
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(NewRelicNormalizer())
