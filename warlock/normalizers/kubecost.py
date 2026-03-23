"""Kubecost normalizer — transforms raw Kubecost API responses into Findings.

Normalizes allocation and assets as inventory; savings opportunities where
estimated savings exist are emitted as misconfiguration findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class KubecostNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Kubecost."""

    HANDLERS: dict[str, str] = {
        "kubecost_allocation": "_normalize_allocation",
        "kubecost_assets": "_normalize_assets",
        "kubecost_savings": "_normalize_savings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "kubecost" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "kubecost",
            "source_type": SourceType.OBSERVABILITY,
            "provider": "kubecost",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_allocation(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        # Kubecost allocation data can be a list of dicts or a single dict
        if isinstance(items, dict):
            items = [items]

        for bucket in items:
            if not isinstance(bucket, dict):
                continue
            for namespace, alloc in bucket.items():
                if not isinstance(alloc, dict):
                    continue
                total_cost = alloc.get("totalCost", 0.0)
                cpu_cost = alloc.get("cpuCost", 0.0)
                ram_cost = alloc.get("ramCost", 0.0)

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Kubecost allocation: {namespace}",
                        detail={
                            "namespace": namespace,
                            "total_cost_usd": total_cost,
                            "cpu_cost_usd": cpu_cost,
                            "ram_cost_usd": ram_cost,
                            "efficiency": alloc.get("totalEfficiency", 0.0),
                        },
                        resource_id=namespace,
                        resource_type="kubecost_allocation",
                        resource_name=namespace,
                        severity="info",
                        confidence=1.0,
                    )
                )

        return findings

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        if isinstance(items, dict):
            items = [items]

        for bucket in items:
            if not isinstance(bucket, dict):
                continue
            for asset_key, asset in bucket.items():
                if not isinstance(asset, dict):
                    continue
                asset_type = asset.get("type", "unknown")
                total_cost = asset.get("totalCost", 0.0)
                name = asset.get("name", asset_key)

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Kubecost asset: {name}",
                        detail={
                            "asset_key": asset_key,
                            "name": name,
                            "type": asset_type,
                            "total_cost_usd": total_cost,
                            "cluster": asset.get("cluster", ""),
                        },
                        resource_id=asset_key,
                        resource_type="kubecost_asset",
                        resource_name=name,
                        severity="info",
                        confidence=1.0,
                    )
                )

        return findings

    def _normalize_savings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        if isinstance(items, dict):
            items = [items]

        for saving in items:
            if not isinstance(saving, dict):
                continue
            saving_type = saving.get("type", saving.get("savingType", "unknown"))
            estimated_monthly = saving.get(
                "monthlySavings", saving.get("estimatedMonthlySavings", 0.0)
            )
            description = saving.get("description", saving_type)

            # Any cost savings opportunity is a misconfiguration (over-provisioning)
            obs_type = "misconfiguration" if float(estimated_monthly or 0) > 0 else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Kubecost savings opportunity: {saving_type}",
                    detail={
                        "saving_type": saving_type,
                        "description": description,
                        "estimated_monthly_savings_usd": estimated_monthly,
                        "resource_count": saving.get("resourceCount", 0),
                    },
                    resource_id=saving_type,
                    resource_type="kubecost_savings",
                    resource_name=saving_type,
                    severity="low" if float(estimated_monthly or 0) > 0 else "info",
                    confidence=0.9,
                )
            )

        return findings


# Register
registry.register(KubecostNormalizer())
