"""Spot.io normalizer — transforms raw Spot.io API responses into Findings.

Normalizes EC2 groups and Ocean clusters as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SpotioNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Spot.io (Spot by NetApp)."""

    HANDLERS: dict[str, str] = {
        "spotio_ec2_groups": "_normalize_ec2_groups",
        "spotio_ocean_clusters": "_normalize_ocean_clusters",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "spotio" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "spotio",
            "source_type": SourceType.CLOUD,
            "provider": "spotio",
            "observed_at": raw.observed_at,
        }

    def _normalize_ec2_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for group in items:
            group_id = str(group.get("id", ""))
            name = group.get("name", "unknown")
            region = group.get("region", "")
            state = group.get("state", "unknown")
            capacity = group.get("capacity", {}) or {}
            target = capacity.get("target", 0) if isinstance(capacity, dict) else 0

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Spot.io Elastigroup: {name}",
                    detail={
                        "group_id": group_id,
                        "name": name,
                        "state": state,
                        "capacity_target": target,
                        "product": group.get("product", ""),
                        "created_at": group.get("createdAt", ""),
                    },
                    resource_id=group_id,
                    resource_type="spotio_ec2_group",
                    resource_name=name,
                    region=region,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_ocean_clusters(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for cluster in items:
            cluster_id = str(cluster.get("id", ""))
            name = cluster.get("name", "unknown")
            region = cluster.get("region", "")
            state = cluster.get("state", "unknown")
            controller_cluster_id = cluster.get("controllerClusterId", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Spot.io Ocean cluster: {name}",
                    detail={
                        "cluster_id": cluster_id,
                        "name": name,
                        "state": state,
                        "controller_cluster_id": controller_cluster_id,
                        "created_at": cluster.get("createdAt", ""),
                    },
                    resource_id=cluster_id,
                    resource_type="spotio_ocean_cluster",
                    resource_name=name,
                    region=region,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SpotioNormalizer())
